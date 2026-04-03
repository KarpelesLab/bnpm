package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/KarpelesLab/slirp"
	"golang.org/x/net/dns/dnsmessage"
)

// Ethernet/IP constants
const (
	etherLen  = 14
	ipv4Len   = 20
	udpHdrLen = 8

	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD

	ipProtoTCP = 6
	ipProtoUDP = 17

	arpRequest = 1
	arpReply   = 2
)

var (
	gatewayMACAddr = [6]byte{0x02, 0x00, 0x0a, 0x00, 0x02, 0x01}
	gatewayIPAddr  = net.IP{10, 0, 2, 1}
	clientIPAddr   = net.IP{10, 0, 2, 100}
)

// netProxy manages the userspace network stack and connection proxying.
type netProxy struct {
	tapFile   *os.File
	stack     *slirp.Stack
	allowList *allowList
	verbose   bool

	clientMAC [6]byte
	gotMAC    bool
	mu        sync.Mutex

	done chan struct{}
	wg   sync.WaitGroup
}

func newNetProxy(tapFile *os.File, profile *Profile, verbose bool) (*netProxy, error) {
	al := newAllowList(profile)
	al.preResolve()

	if verbose {
		fmt.Fprintf(os.Stderr, "bnpm: network allow list: %s\n", al)
	}

	np := &netProxy{
		tapFile:   tapFile,
		stack:     slirp.New(),
		allowList: al,
		verbose:   verbose,
		done:      make(chan struct{}),
	}

	np.wg.Add(1)
	go np.readLoop()

	return np, nil
}

func (np *netProxy) Close() {
	close(np.done)
	np.tapFile.Close()
	np.stack.Close()
	np.wg.Wait()
}

// writer returns a slirp.Writer that sends Ethernet frames to the TAP device.
func (np *netProxy) writer() slirp.Writer {
	return func(frame []byte) error {
		_, err := np.tapFile.Write(frame)
		return err
	}
}

// readLoop reads frames from the TAP device and dispatches them.
func (np *netProxy) readLoop() {
	defer np.wg.Done()
	buf := make([]byte, 65536)
	w := np.writer()

	for {
		select {
		case <-np.done:
			return
		default:
		}

		n, err := np.tapFile.Read(buf)
		if err != nil {
			select {
			case <-np.done:
				return
			default:
				if np.verbose {
					fmt.Fprintf(os.Stderr, "bnpm: TAP read error: %v\n", err)
				}
				return
			}
		}
		if n < etherLen {
			continue
		}

		frame := buf[:n]

		// Learn client MAC
		np.mu.Lock()
		if !np.gotMAC {
			copy(np.clientMAC[:], frame[6:12])
			np.gotMAC = true
		}
		clientMAC := np.clientMAC
		np.mu.Unlock()

		etherType := binary.BigEndian.Uint16(frame[12:14])

		switch etherType {
		case etherTypeARP:
			np.handleARP(frame)

		case etherTypeIPv4, etherTypeIPv6:
			ipPkt := frame[etherLen:]
			if np.filterPacket(ipPkt) {
				np.stack.HandlePacket(0, clientMAC, gatewayMACAddr, ipPkt, w)
			}
		}
	}
}

// filterPacket checks if an IP packet should be allowed through.
// Returns true if allowed, false if blocked.
// Also intercepts DNS queries (UDP port 53) for domain filtering.
func (np *netProxy) filterPacket(ipPkt []byte) bool {
	if len(ipPkt) < ipv4Len {
		return false
	}

	version := ipPkt[0] >> 4
	if version != 4 {
		// Allow IPv6 through for now (could add filtering later)
		return true
	}

	ihl := int(ipPkt[0]&0x0f) * 4
	if ihl < ipv4Len || len(ipPkt) < ihl {
		return false
	}

	proto := ipPkt[9]
	var dstIP [4]byte
	copy(dstIP[:], ipPkt[16:20])
	dstAddr, _ := netip.AddrFromSlice(dstIP[:])

	switch proto {
	case ipProtoTCP:
		if len(ipPkt) < ihl+20 {
			return false
		}
		tcp := ipPkt[ihl:]
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		flags := tcp[13]

		// Only filter on SYN (new connections); allow data on established
		if flags&0x02 != 0 && flags&0x10 == 0 {
			// SYN without ACK = new connection
			if !np.allowList.isAllowed(dstAddr, dstPort) {
				if np.verbose {
					fmt.Fprintf(os.Stderr, "bnpm: BLOCKED tcp %s:%d\n", dstAddr, dstPort)
				}
				np.sendTCPReset(ipPkt[:ihl], tcp)
				return false
			}
			if np.verbose {
				fmt.Fprintf(os.Stderr, "bnpm: ALLOW tcp %s:%d\n", dstAddr, dstPort)
			}
		}
		return true

	case ipProtoUDP:
		if len(ipPkt) < ihl+udpHdrLen {
			return false
		}
		udp := ipPkt[ihl:]
		dstPort := binary.BigEndian.Uint16(udp[2:4])

		if dstPort == 53 {
			// Intercept DNS — handle ourselves, don't pass to slirp
			np.handleDNS(ipPkt[:ihl], udp)
			return false
		}

		// Non-DNS UDP: check allow list
		if !np.allowList.isAllowed(dstAddr, dstPort) {
			if np.verbose {
				fmt.Fprintf(os.Stderr, "bnpm: BLOCKED udp %s:%d\n", dstAddr, dstPort)
			}
			return false
		}
		return true

	default:
		// ICMP etc — drop (slirp doesn't handle ICMPv4 anyway)
		return false
	}
}

// handleARP responds to ARP requests for the gateway IP.
func (np *netProxy) handleARP(frame []byte) {
	if len(frame) < etherLen+28 {
		return
	}
	arpData := frame[etherLen:]
	opcode := binary.BigEndian.Uint16(arpData[6:8])
	if opcode != arpRequest {
		return
	}

	targetIP := arpData[24:28]
	if !net.IP(targetIP).Equal(gatewayIPAddr) {
		return
	}

	reply := make([]byte, etherLen+28)
	copy(reply[0:6], frame[6:12])              // dst = original sender
	copy(reply[6:12], gatewayMACAddr[:])        // src = gateway
	binary.BigEndian.PutUint16(reply[12:14], etherTypeARP)

	arp := reply[etherLen:]
	binary.BigEndian.PutUint16(arp[0:2], 1)    // hardware: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x800) // protocol: IPv4
	arp[4] = 6                                   // hw size
	arp[5] = 4                                   // proto size
	binary.BigEndian.PutUint16(arp[6:8], arpReply)
	copy(arp[8:14], gatewayMACAddr[:])  // sender MAC
	copy(arp[14:18], gatewayIPAddr)     // sender IP
	copy(arp[18:24], arpData[8:14])     // target MAC (original sender's MAC)
	copy(arp[24:28], arpData[14:18])    // target IP (original sender's IP)

	np.tapFile.Write(reply)
}

// sendTCPReset sends a RST packet back through the TAP for a denied TCP SYN.
func (np *netProxy) sendTCPReset(ipHdr, tcpHdr []byte) {
	srcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
	clientSeq := binary.BigEndian.Uint32(tcpHdr[4:8])

	np.mu.Lock()
	clientMAC := np.clientMAC
	np.mu.Unlock()

	// Build RST+ACK: Ethernet(14) + IP(20) + TCP(20)
	pkt := make([]byte, etherLen+20+20)

	// Ethernet header
	copy(pkt[0:6], clientMAC[:])
	copy(pkt[6:12], gatewayMACAddr[:])
	binary.BigEndian.PutUint16(pkt[12:14], etherTypeIPv4)

	// IP header (swap src/dst from original)
	ip := pkt[etherLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40) // total length
	ip[8] = 64                                // TTL
	ip[9] = ipProtoTCP
	copy(ip[12:16], ipHdr[16:20]) // src = original dst (remote)
	copy(ip[16:20], ipHdr[12:16]) // dst = original src (client)
	binary.BigEndian.PutUint16(ip[10:12], slirp.IPChecksum(ip[:20]))

	// TCP header (swap ports)
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], dstPort)  // src = original dst
	binary.BigEndian.PutUint16(tcp[2:4], srcPort)   // dst = original src
	binary.BigEndian.PutUint32(tcp[4:8], 0)          // seq
	binary.BigEndian.PutUint32(tcp[8:12], clientSeq+1) // ack
	tcp[12] = 0x50                                    // data offset = 5 words
	tcp[13] = 0x14                                    // RST+ACK
	binary.BigEndian.PutUint16(tcp[14:16], 0)         // window
	binary.BigEndian.PutUint16(tcp[16:18], slirp.TCPChecksum(ip[12:16], ip[16:20], tcp[:20], nil))

	np.tapFile.Write(pkt)
}

// handleDNS processes DNS queries, filters by domain, and responds.
func (np *netProxy) handleDNS(ipHdr, udpPkt []byte) {
	if len(udpPkt) < udpHdrLen {
		return
	}

	srcPort := binary.BigEndian.Uint16(udpPkt[0:2])
	payload := udpPkt[udpHdrLen:]
	if len(payload) == 0 {
		return
	}

	// Parse DNS query
	var parser dnsmessage.Parser
	hdr, err := parser.Start(payload)
	if err != nil {
		return
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) == 0 {
		return
	}

	domain := questions[0].Name.String()

	if !np.allowList.isDomainAllowed(domain) {
		if np.verbose {
			fmt.Fprintf(os.Stderr, "bnpm: BLOCKED dns %s\n", domain)
		}
		resp := buildNXDomain(hdr.ID, questions[0])
		if resp != nil {
			np.sendUDPResponse(ipHdr, srcPort, 53, resp)
		}
		return
	}

	if np.verbose {
		fmt.Fprintf(os.Stderr, "bnpm: ALLOW dns %s\n", domain)
	}

	resp, resolvedIPs := forwardDNS(payload, domain)
	if resp == nil {
		return
	}

	// Add resolved IPs to dynamic allow list
	for _, ip := range resolvedIPs {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			np.allowList.mu.Lock()
			np.allowList.resolvedIPs[addr.Unmap()] = true
			np.allowList.mu.Unlock()
		}
	}

	np.sendUDPResponse(ipHdr, srcPort, 53, resp)
}

// sendUDPResponse sends a UDP response back through the TAP.
func (np *netProxy) sendUDPResponse(origIPHdr []byte, clientPort, serverPort uint16, payload []byte) {
	np.mu.Lock()
	clientMAC := np.clientMAC
	np.mu.Unlock()

	var srcIP, dstIP [4]byte
	copy(srcIP[:], origIPHdr[16:20]) // original dst = our src
	copy(dstIP[:], origIPHdr[12:16]) // original src = our dst

	ipHdrLen := 20
	totalLen := etherLen + ipHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	// Ethernet
	copy(pkt[0:6], clientMAC[:])
	copy(pkt[6:12], gatewayMACAddr[:])
	binary.BigEndian.PutUint16(pkt[12:14], etherTypeIPv4)

	// IP
	ip := pkt[etherLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+udpHdrLen+len(payload)))
	ip[8] = 64
	ip[9] = ipProtoUDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], slirp.IPChecksum(ip[:ipHdrLen]))

	// UDP
	udp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], serverPort)
	binary.BigEndian.PutUint16(udp[2:4], clientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+len(payload)))
	copy(udp[udpHdrLen:], payload)
	binary.BigEndian.PutUint16(udp[6:8], slirp.UDPChecksum(ip[12:16], ip[16:20], udp[:udpHdrLen], payload))

	np.tapFile.Write(pkt)
}

// forwardDNS sends a DNS query to the host resolver and returns the response
// along with any resolved IP addresses.
func forwardDNS(query []byte, domain string) ([]byte, []net.IP) {
	resolvers := []string{"127.0.0.53:53", "8.8.8.8:53", "1.1.1.1:53"}

	for _, resolver := range resolvers {
		dnsConn, err := net.DialTimeout("udp", resolver, 2*time.Second)
		if err != nil {
			continue
		}

		dnsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := dnsConn.Write(query); err != nil {
			dnsConn.Close()
			continue
		}

		resp := make([]byte, 4096)
		n, err := dnsConn.Read(resp)
		dnsConn.Close()
		if err != nil {
			continue
		}

		var ips []net.IP
		var parser dnsmessage.Parser
		if _, err := parser.Start(resp[:n]); err == nil {
			parser.SkipAllQuestions()
			for {
				rr, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				switch rr.Type {
				case dnsmessage.TypeA:
					r, err := parser.AResource()
					if err == nil {
						ips = append(ips, net.IP(r.A[:]))
					}
				case dnsmessage.TypeAAAA:
					r, err := parser.AAAAResource()
					if err == nil {
						ips = append(ips, net.IP(r.AAAA[:]))
					}
				default:
					parser.SkipAnswer()
				}
			}
		}

		return resp[:n], ips
	}

	return nil, nil
}

// buildNXDomain constructs a DNS NXDOMAIN response.
func buildNXDomain(id uint16, q dnsmessage.Question) []byte {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		RCode:              dnsmessage.RCodeNameError,
		RecursionDesired:   true,
		RecursionAvailable: true,
	})
	builder.StartQuestions()
	builder.Question(q)
	msg, err := builder.Finish()
	if err != nil {
		return nil
	}
	return msg
}
