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

const (
	ipv4Len   = 20
	udpHdrLen = 8

	ipProtoTCP = 6
	ipProtoUDP = 17
)

// netProxy manages the userspace network stack and connection proxying.
type netProxy struct {
	tunFile   *os.File
	stack     *slirp.Stack
	allowList *allowList
	verbose   bool

	done chan struct{}
	wg   sync.WaitGroup
}

func newNetProxy(tunFile *os.File, profile *Profile, verbose bool) (*netProxy, error) {
	al := newAllowList(profile)
	al.preResolve()

	if verbose {
		fmt.Fprintf(os.Stderr, "bnpm: network allow list: %s\n", al)
	}

	np := &netProxy{
		tunFile:   tunFile,
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
	np.tunFile.Close()
	np.stack.Close()
	np.wg.Wait()
}

// writer returns a slirp.Writer that sends IP packets to the TUN device.
func (np *netProxy) writer() slirp.Writer {
	return func(pkt []byte) error {
		_, err := np.tunFile.Write(pkt)
		return err
	}
}

// readLoop reads IP packets from the TUN device and dispatches them.
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

		n, err := np.tunFile.Read(buf)
		if err != nil {
			select {
			case <-np.done:
				return
			default:
				if np.verbose {
					fmt.Fprintf(os.Stderr, "bnpm: TUN read error: %v\n", err)
				}
				return
			}
		}
		if n < ipv4Len {
			continue
		}

		ipPkt := make([]byte, n)
		copy(ipPkt, buf[:n])

		if np.filterPacket(ipPkt) {
			np.stack.HandlePacket(0, ipPkt, w)
		}
	}
}

// filterPacket checks if an IP packet should be allowed through.
// Returns true if allowed, false if blocked.
// Intercepts DNS queries (UDP port 53) for domain filtering.
func (np *netProxy) filterPacket(ipPkt []byte) bool {
	if len(ipPkt) < ipv4Len {
		return false
	}

	version := ipPkt[0] >> 4
	if version != 4 {
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
			np.handleDNS(ipPkt[:ihl], udp)
			return false
		}

		if !np.allowList.isAllowed(dstAddr, dstPort) {
			if np.verbose {
				fmt.Fprintf(os.Stderr, "bnpm: BLOCKED udp %s:%d\n", dstAddr, dstPort)
			}
			return false
		}
		return true

	default:
		return false
	}
}

// sendTCPReset sends a RST packet back through the TUN for a denied TCP SYN.
func (np *netProxy) sendTCPReset(ipHdr, tcpHdr []byte) {
	srcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
	clientSeq := binary.BigEndian.Uint32(tcpHdr[4:8])

	// Build RST+ACK: IP(20) + TCP(20)
	pkt := make([]byte, 40)

	// IP header (swap src/dst from original)
	ip := pkt
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = ipProtoTCP
	copy(ip[12:16], ipHdr[16:20]) // src = original dst
	copy(ip[16:20], ipHdr[12:16]) // dst = original src
	binary.BigEndian.PutUint16(ip[10:12], slirp.IPChecksum(ip[:20]))

	// TCP header (swap ports)
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], dstPort)
	binary.BigEndian.PutUint16(tcp[2:4], srcPort)
	binary.BigEndian.PutUint32(tcp[8:12], clientSeq+1) // ack
	tcp[12] = 0x50                                      // data offset = 5 words
	tcp[13] = 0x14                                      // RST+ACK
	binary.BigEndian.PutUint16(tcp[16:18], slirp.TCPChecksum(ip[12:16], ip[16:20], tcp[:20], nil))

	np.tunFile.Write(pkt)
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

	for _, ip := range resolvedIPs {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			np.allowList.mu.Lock()
			np.allowList.resolvedIPs[addr.Unmap()] = true
			np.allowList.mu.Unlock()
		}
	}

	np.sendUDPResponse(ipHdr, srcPort, 53, resp)
}

// sendUDPResponse sends a UDP response back through the TUN.
func (np *netProxy) sendUDPResponse(origIPHdr []byte, clientPort, serverPort uint16, payload []byte) {
	ipHdrLen := 20
	totalLen := ipHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	// IP header
	ip := pkt
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64
	ip[9] = ipProtoUDP
	copy(ip[12:16], origIPHdr[16:20]) // src = original dst
	copy(ip[16:20], origIPHdr[12:16]) // dst = original src
	binary.BigEndian.PutUint16(ip[10:12], slirp.IPChecksum(ip[:ipHdrLen]))

	// UDP header
	udp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], serverPort)
	binary.BigEndian.PutUint16(udp[2:4], clientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+len(payload)))
	copy(udp[udpHdrLen:], payload)
	binary.BigEndian.PutUint16(udp[6:8], slirp.UDPChecksum(ip[12:16], ip[16:20], udp[:udpHdrLen], payload))

	np.tunFile.Write(pkt)
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
