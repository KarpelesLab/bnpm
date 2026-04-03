package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunName    = "tun0"
	tunIP      = "10.0.2.100"
	tunGateway = "10.0.2.1"
	tunMask    = 24
	tunMTU     = 1500
)

// setupNetworkProxy receives the TUN fd from the child (via Unix socket)
// and starts the userspace network proxy. Returns a cleanup function.
func setupNetworkProxy(parentSock *os.File, profile *Profile, verbose bool) (func(), error) {
	// Receive TUN fd from child via SCM_RIGHTS
	conn, err := net.FileConn(parentSock)
	if err != nil {
		return nil, fmt.Errorf("FileConn: %w", err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("not a unix conn")
	}

	buf := make([]byte, 32)
	oob := make([]byte, unix.CmsgLen(4))
	_, oobn, _, _, err := unixConn.ReadMsgUnix(buf, oob)
	unixConn.Close()
	if err != nil {
		return nil, fmt.Errorf("ReadMsgUnix: %w", err)
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}

	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("ParseUnixRights: %w", err)
	}

	tunFd := fds[0]
	// Set non-blocking so Go's runtime poller manages the fd.
	// This lets Close() properly unblock a concurrent Read().
	unix.SetNonblock(tunFd, true)
	tunFile := os.NewFile(uintptr(tunFd), "tun0")

	if verbose {
		fmt.Fprintf(os.Stderr, "bnpm: received TUN fd %d from child\n", tunFd)
	}

	// Start the userspace network proxy
	proxy, err := newNetProxy(tunFile, profile, verbose)
	if err != nil {
		tunFile.Close()
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	cleanup := func() {
		proxy.Close()
		tunFile.Close()
	}

	return cleanup, nil
}

// childSetupNetwork creates a TUN device in the child's network namespace,
// configures it, and sends the fd back to the parent.
func childSetupNetwork(sockFd int) error {
	// Bring up loopback
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		netlink.LinkSetUp(lo)
	}

	// Create TUN device
	tunFd, err := createTUN(tunName)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}

	// Configure TUN device via netlink
	tun, err := netlink.LinkByName(tunName)
	if err != nil {
		unix.Close(tunFd)
		return fmt.Errorf("find TUN link: %w", err)
	}

	if err := netlink.LinkSetMTU(tun, tunMTU); err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: warning: set TUN MTU: %v\n", err)
	}

	addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", tunIP, tunMask))
	if err := netlink.AddrAdd(tun, addr); err != nil {
		unix.Close(tunFd)
		return fmt.Errorf("add TUN addr: %w", err)
	}

	if err := netlink.LinkSetUp(tun); err != nil {
		unix.Close(tunFd)
		return fmt.Errorf("TUN up: %w", err)
	}

	gw := net.ParseIP(tunGateway)
	route := &netlink.Route{Gw: gw}
	if err := netlink.RouteAdd(route); err != nil {
		unix.Close(tunFd)
		return fmt.Errorf("add route: %w", err)
	}

	// Send TUN fd to parent via SCM_RIGHTS
	rights := unix.UnixRights(tunFd)
	err = unix.Sendmsg(sockFd, []byte("tun"), rights, nil, 0)
	if err != nil {
		unix.Close(tunFd)
		return fmt.Errorf("sendmsg TUN fd: %w", err)
	}

	// Close our copy — parent has it now
	unix.Close(tunFd)

	return nil
}

// createTUN creates a TUN device and returns its file descriptor.
func createTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// Build ifreq struct: IFNAMSIZ (16) bytes name + uint16 flags
	var ifr [40]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	// IFF_TUN=0x0001 | IFF_NO_PI=0x1000 = 0x1001
	binary.NativeEndian.PutUint16(ifr[unix.IFNAMSIZ:], 0x0001|0x1000)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	return fd, nil
}
