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
	tapName    = "tap0"
	tapIP      = "10.0.2.100"
	tapGateway = "10.0.2.1"
	tapMask    = 24
	tapMTU     = 1500
)

// setupNetworkProxy receives the TAP fd from the child (via Unix socket)
// and starts the userspace network proxy. Returns a cleanup function.
func setupNetworkProxy(parentSock *os.File, profile *Profile, verbose bool) (func(), error) {
	// Receive TAP fd from child via SCM_RIGHTS
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

	tapFd := fds[0]
	// Set non-blocking so Go's runtime poller manages the fd.
	// This lets Close() properly unblock a concurrent Read().
	unix.SetNonblock(tapFd, true)
	tapFile := os.NewFile(uintptr(tapFd), "tap0")

	if verbose {
		fmt.Fprintf(os.Stderr, "bnpm: received TAP fd %d from child\n", tapFd)
	}

	// Start the userspace network proxy
	proxy, err := newNetProxy(tapFile, profile, verbose)
	if err != nil {
		tapFile.Close()
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	cleanup := func() {
		proxy.Close()
		tapFile.Close()
	}

	return cleanup, nil
}

// childSetupNetwork creates a TAP device in the child's network namespace,
// configures it, and sends the fd back to the parent.
func childSetupNetwork(sockFd int) error {
	// Bring up loopback
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		netlink.LinkSetUp(lo)
	}

	// Create TAP device
	tapFd, err := createTAP(tapName)
	if err != nil {
		return fmt.Errorf("create TAP: %w", err)
	}

	// Configure TAP device via netlink
	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		unix.Close(tapFd)
		return fmt.Errorf("find TAP link: %w", err)
	}

	if err := netlink.LinkSetMTU(tap, tapMTU); err != nil {
		// Non-fatal
		fmt.Fprintf(os.Stderr, "bnpm: warning: set TAP MTU: %v\n", err)
	}

	addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", tapIP, tapMask))
	if err := netlink.AddrAdd(tap, addr); err != nil {
		unix.Close(tapFd)
		return fmt.Errorf("add TAP addr: %w", err)
	}

	if err := netlink.LinkSetUp(tap); err != nil {
		unix.Close(tapFd)
		return fmt.Errorf("TAP up: %w", err)
	}

	gw := net.ParseIP(tapGateway)
	route := &netlink.Route{Gw: gw}
	if err := netlink.RouteAdd(route); err != nil {
		unix.Close(tapFd)
		return fmt.Errorf("add route: %w", err)
	}

	// Send TAP fd to parent via SCM_RIGHTS
	rights := unix.UnixRights(tapFd)
	err = unix.Sendmsg(sockFd, []byte("tap"), rights, nil, 0)
	if err != nil {
		unix.Close(tapFd)
		return fmt.Errorf("sendmsg TAP fd: %w", err)
	}

	// Close our copy of the TAP fd — parent has it now
	unix.Close(tapFd)

	return nil
}

// createTAP creates a TAP device and returns its file descriptor.
func createTAP(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// Build ifreq struct: IFNAMSIZ (16) bytes name + uint16 flags
	var ifr [40]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	// IFF_TAP=0x0002 | IFF_NO_PI=0x1000 = 0x1002
	binary.NativeEndian.PutUint16(ifr[unix.IFNAMSIZ:], 0x0002|0x1000)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	return fd, nil
}
