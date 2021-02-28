//
// Call some socket-based server and converse with it, passing stdin to it
// and writing its output to stdout. We support TCP, Unix sockets, SSL/TLS,
// and UDP (which may or may not work for you), among other things.
// We can optionally listen for connections instead and then converse with
// with them. This gets complex for UDP (and Unix datagram); see later.
//
// usage: call [-lPHRTqh] [-b address] [-B bufsize] [-C NUM] [proto] {address | host port}
//
// Note that you have to specify each flag separately. Sigh.
//
//    -h: show brief usage
//    -P means list known protocols with some information.
//    -q means to be quieter in some situations.
//    -v means to be more verbose in some situations.
//    -T reports TLS connection and server certificate information.
//    -I doesn't verify TLS server certificates on connections
//    -b means to use the address as the local address when making outgoing
//       connections (ie, not with -l). For TCP and UDP, if the address
//       lacks a ':' it's assumed to be a hostname or IP address.
//    -t sets a connection timeout for outgoing connections.
//    -l means listen as a server. This behaves differently for stream and
//       datagram protocols and does not support TLS/SSL (yet).
//    -C NUM means only listen for NUM connections during -l, then exit.
//    -B BYTES sets the buffer size for (network) IO; this is potentially
//       important for 10G Ethernet. The default buffer size is 128 KBytes.
//    -H prints datagram data in hex when in -l.
//    -R simply receives datagram data when in -l.
//    -N converts newlines in the input data to CR NL when sent to the network
//    -L appends a newline when printing datagrams that lack them when in -l.
//
// [proto] is a protocol supported by the go net package plus some other
// options. See call -P. Not all supported protocols are useful or
// functional in practice, eg probably ip* and unixgram.
//
// Address is 'host:port' for IP protocols; 'host' may be omitted.
// 'call :port' means 'call on localhost'; 'call -l :port' means
// 'listen generally'. The 'host port' form of this is only
// appropriate for protocols that take both hosts and ports.
//
// Note that go's TLS implementation sends SNI information, so if you
// are testing a web server the Host: you provide must match the
// actual hostname you gave call.
//
// -l for stream protocols accepts one connection at a time and converses
// with it until stdin EOF, then repeats this.
//
// -l for datagram protocols accepts and prints packets from anywhere.
// When it receives a packet and it is not already sending stdin to
// somewhere, it starts sending stdin to that source until EOF. After
// EOF this repeats. This behavior is disabled with -R; with -R, -l
// never sends anything, it just receives.
//
// -H and -R only have any effect if you're listening for datagram
// protocols.
//
// -N is a feature intended for talking to picky network services
// for protocols that specify that the line ending is CR NL, not a
// bare NL. Most servers accept a bare NL as the line ending for eg
// SMTP, but a few servers really insist on CR NL. Note that the
// NL to CR NL conversion happens for all NLs in the input, even if
// there's already a CR before them. Arguably this is a bug.
//
// BUGS: this has too many options (because Chris got enthusiastic).
//
// Author: Chris Siebenmann
// https://github.com/siebenmann/call
//
// Copyright: GPL v3
//
package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// an enum, basically.
type shutdowns int

const (
	readShutdown shutdowns = iota
	writeShutdown
)

// DEFAULTNETBUF is the default network buffer size
const DEFAULTNETBUF = (128 * 1024)

// These should probably be using the log package, or be replaced by it.

// Fprintf to stderr, putting our program name on the front.
func warnf(format string, elems ...interface{}) {
	fmt.Fprintf(os.Stderr, "call: "+format, elems...)
}

// Fprintln to stderr, putting our program name on the front.
func warnln(elems ...interface{}) {
	e := append([]interface{}{"call:"}, elems...)
	fmt.Fprintln(os.Stderr, e...)
}

// ---
// Global options
var quiet bool     // -q
var verbose bool   // -v
var reporttls bool // -T
var dgramhex bool  // -H
var recvonly bool  // -R
var conns int      // -C NUM, 0 is 'not enabled'
var bufsize int    // -B bufsize, default is 128k
var convnl bool    // Convert NL in input to CR NL to the network
var addnl bool     // Add a newline after records on receive if they lack them.
var insec bool     // Do not verify TLS certificates

// ---
// Stream socket conversation support routines.
// These also work for *sending* to datagram sockets, but you can't use
// them when listening on datagram sockets.

// read from src, write to dst, put imsg or omsg in the error message if
// something happens. No error message is printed for EOF on src.
func fromto(src io.Reader, dst io.Writer, imsg, omsg string) {
	var rerr, werr error
	buf := make([]byte, bufsize)

	for rerr == nil && werr == nil {
		var n int
		n, rerr = src.Read(buf[0:])
		// It would be really nice if we could catch and
		// recognize 'use of closed network connection' errors
		// because, well, THEY AREN'T. Welcome to the land of
		// goroutines.
		if rerr != nil && rerr != io.EOF {
			warnln(imsg, "read error:", rerr)
		}
		// if n is 0 this does nothing.
		_, werr = dst.Write(buf[0:n])
		if werr != nil {
			warnln(omsg, "write error:", werr)
		}
	}
}

// crnlWriter is an io.Writer that turns NL into CR NL on output to an
// underlying io.Writer. As a result it may make multiple io.Write calls.
type crnlWriter struct {
	dst io.Writer
}

func (cn *crnlWriter) Write(buf []byte) (int, error) {
	var werr error
	var cnt, idx int

	// We cannot use bytes.Split() / bytes.SplitAfter() because it
	// obscures the case of a block of input without a NL at all.
	// TODO: the standard library probably has something to deal
	// with this.
	n := len(buf)
	for i := 0; i < n && werr == nil; i = idx + 1 {
		var t int
		idx = bytes.IndexByte(buf[i:n], '\n')
		if idx == -1 {
			t, werr = cn.dst.Write(buf[i:n])
			idx = n
			cnt += t
		} else {
			idx += i
			t, werr = cn.dst.Write(buf[i:idx])
			cnt += t
			if werr == nil {
				_, werr = cn.dst.Write([]byte("\r\n"))
				// cnt is how far we've gone through
				// the buffer, not how many bytes we've
				// written to the underlying channel.
				// So we must advance it by only one
				// here.
				cnt++
			}
		}
	}
	return cnt, werr
}

// copy stdin to remote, send readShutdown to master on end.
func tonet(remote net.Conn, master chan shutdowns) {
	var rem io.Writer
	if convnl {
		rem = &crnlWriter{dst: remote}
	} else {
		rem = remote
	}
	fromto(os.Stdin, rem, "stdin", "network")
	master <- readShutdown
}

// copy remote to stdout, send writeShutdown to master on end.
func fromnet(remote net.Conn, master chan shutdowns) {
	fromto(remote, os.Stdout, "network", "stdout")
	master <- writeShutdown
}

// Do CloseWrite() aka shutdown(fd, 1) on conn if possible; we exploit
// interfaces to do this relatively generically.
// Return true if we could, false otherwise.
// See http://utcc.utoronto.ca/~cks/space/blog/programming/GoInterfacePunning
// for an explanation of how this works.

// Closer is the interface type of things that can do a shutdown().
type Closer interface {
	CloseRead() error
	CloseWrite() error
}

func shutdownWrite(conn net.Conn) bool {
	if v, ok := conn.(Closer); ok {
		_ = v.CloseWrite()
		return true
	}
	return false
}

// Hold a conversation over a connection.
// copy stdin to conn, copy conn to stdout, do magic shutdown things as
// necessary. server is true if we are handling the server side and should
// exit on stdin EOF instead of network EOF.
// NOTE: we close conn when we return.
func converse(conn net.Conn, server bool) {
	master := make(chan shutdowns)
	go tonet(conn, master)
	go fromnet(conn, master)
	for {
		r := <-master
		if r == readShutdown {
			// If we are using a protocol where we can't
			// shut down writes on stdin EOF, the right
			// thing to do now is to exit.
			// ... or at least the convenient thing, as far
			// as Chris is concerned.
			if !shutdownWrite(conn) || server {
				break
			}
		} else {
			if !server {
				// If network input shuts down, we
				// shut down totally.  This is the
				// most useful thing to do in
				// practice.
				break
			} else {
				nonquiet("<EOF from network>")
			}
		}
	}
	// In server operation this brutally shoots our fromnet()
	// goroutine in the head. Unfortunately we have no graceful
	// way to break it out of its read.
	// (In client operation we don't care so much about stranding
	// our read of stdin, although things can happen there too!)
	_ = conn.Close()
}

// ---

// ---
// Datagram/packet listener support routines.

// receive packets from conn, print them to stdout, and send the address
// of each packet upstream to our master.
// The data packets are assumed to have embedded newlines, which may be
// false.
func packetRecv(conn net.PacketConn, master chan net.Addr) {
	buf := make([]byte, bufsize)
	for {
		var bufStr string

		n, addr, err := conn.ReadFrom(buf[0:])
		if err != nil {
			warnln("error on ReadFrom:", err)
			return
		}

		// TODO: can n ever be 0?
		if dgramhex {
			bufStr = fmt.Sprintf("0x % x\n", buf[:n])
		} else {
			bufStr = string(buf[:n])
		}
		if addnl && buf[n] != '\n' {
			bufStr += "\n"
		}

		if quiet {
			fmt.Printf("%s", bufStr)
		} else {
			fmt.Printf("%s > %s", addr, bufStr)
		}

		// We print packet details before sending the address
		// upstream in case this send blocks.
		master <- addr
	}
}

// Send stdin packets to addr via conn until EOF, then signal master with
// readShutdown.
// If we experience a short write, we just warn about it and discard the
// unwritten data; this is basically required by packet-based connection
// types, since two packets != one big packet.
func packetSend(conn net.PacketConn, addr net.Addr, master chan shutdowns) {
	buf := make([]byte, bufsize)
	for {
		nr, err := os.Stdin.Read(buf[0:])
		if err != nil {
			// We do not attempt to write partial data on a
			// stdin read error.
			if err != io.EOF {
				warnln("stdin read error:", err)
			}
			break
		}
		nw, err := conn.WriteTo(buf[0:nr], addr)
		if err != nil {
			warnln("network write error to", addr, ":", err)
			break
		}
		if nr != nw {
			warnf("short write to %s: %d written of %d\n",
				addr, nw, nr)
		}
	}
	master <- readShutdown
}

// A packet-based listen.
func listenpacket(proto, addr string) {
	conn, err := net.ListenPacket(proto, addr)
	if err != nil {
		warnf("error listening %s!%s: %s\n", proto, addr, err)
		return
	}

	schan := make(chan shutdowns)
	mchan := make(chan net.Addr)
	go packetRecv(conn, mchan)
	for {
		addr := <-mchan
		if recvonly {
			continue
		}
		fmt.Println("call: sending stdin to", addr, "until EOF.")
		go packetSend(conn, addr, schan)
		goon := true
		for goon {
			// While we have an active stdin -> network copy,
			// we simply discard incoming packet addresses and
			// wait for the EOF signal from packetSend().
			select {
			case <-mchan:
			case <-schan:
				goon = false
			}
		}
		fmt.Println("call: stdin EOF, send to", addr, "done.")
	}
	// We never reach here so calling conn.Close() here is unreachable
	// code.
}

// ---

// fmt.Println if quiet is not set.
func nonquiet(elems ...interface{}) {
	if !quiet {
		fmt.Println(elems...)
	}
}

// Stream based listening.
func listen(proto, addr string) {
	conn, err := net.Listen(proto, addr)
	if err != nil {
		warnf("error listening %s!%s: %s\n", proto, addr, err)
		return
	}
	cxns := 0

	for conns <= 0 || cxns < conns {
		nc, err := conn.Accept()
		if err == nil {
			nonquiet("call: connection from:", nc.RemoteAddr())
			converse(nc, true)
			nonquiet("call: connection done")
		}
		cxns++
	}
	_ = conn.Close()
}

// ---
// Client side conversation in general

// ResolveAddr turns a proto plus address pair into a net.Addr.
// BUG: This should be in the net package, not here.
func ResolveAddr(proto, addr string) (net.Addr, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if !strings.Contains(addr, ":") {
			addr += ":0"
		}
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return net.ResolveTCPAddr(proto, addr)
	case "udp", "udp4", "udp6":
		return net.ResolveUDPAddr(proto, addr)
	case "ip", "ip4", "ip6":
		return net.ResolveIPAddr(proto, addr)
	case "unix", "unixpacket", "unixgram":
		return net.ResolveUnixAddr(proto, addr)
	}
	return nil, errors.New("cannot resolve address for protocol: " + proto)
}

// We accept 'ssl'/'tls' as a protocol; it implies 'tcp' as the underlying
// protocol.
func dial(proto, addr, laddr string, tmout time.Duration) (net.Conn, error) {
	// Set up our dialer options; we may need a local address and/or
	// a connection timeout.
	// TODO: happy eyeballs support, ie dialer.DualStack? This might be
	// worth a command line switch.
	var dialer net.Dialer
	dialer.Timeout = tmout
	if laddr != "" {
		a, e := ResolveAddr(proto, laddr)
		if e != nil {
			return nil, e
		}
		dialer.LocalAddr = a
	}

	switch proto {
	case "ssl", "tls":
		// In 2021, TLS connections should verify server
		// certificates by default.
		cfg := tls.Config{}
		if insec {
			cfg.InsecureSkipVerify = true
		}
		return tls.DialWithDialer(&dialer, "tcp", addr, &cfg)
	}
	return dialer.Dial(proto, addr)
}

func tlsinfo(c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	cs := tc.ConnectionState()
	cname := cipherSuiteName(cs.CipherSuite)
	// there should always be at least one peer certificate.
	// The first peer certificate is the certificate of the host
	// itself, which is what we wanted.
	pcert := cs.PeerCertificates[0]
	// Some TLS certificates lack a CN and have all associated DNS
	// names in pcert.DNSNames. We don't try to fix this up here,
	// just report that the CN is missing.
	cn := pcert.Subject.CommonName
	if cn == "" {
		cn = "<no CN>"
	}
	warnf("TLS to TLS host %s with %s\n", cn, cname)
	// Only report DNS names that are different from the CN, ie
	// report additional names. We don't check that the CN is
	// included in DNSNames or anything; we're reporting
	// information, not alerting about oddities.
	//
	// (We could report all of DNSNames, but it's nicer to trim it
	// down slightly. Some of the time this lets us not report
	// altnames at all, since it's a single entry duplicate of the
	// CN.)
	var altnames []string
	for _, s := range pcert.DNSNames {
		if s != pcert.Subject.CommonName {
			altnames = append(altnames, s)
		}
	}
	if len(altnames) > 0 && verbose {
		warnf("alt names: %s; valid %s to %s\n", strings.Join(altnames, ", "), pcert.NotBefore.Format("2006-01-02"), pcert.NotAfter.Format("2006-01-02"))
	} else if verbose {
		warnf("valid %s to %s\n", pcert.NotBefore.Format("2006-01-02"), pcert.NotAfter.Format("2006-01-02"))
	}
}

func call(proto, addr, laddr string, tmout time.Duration) {
	conn, err := dial(proto, addr, laddr, tmout)
	if err != nil {
		warnf("error dialing %s!%s: %s\n", proto, addr, err)
		return
	}
	if reporttls {
		tlsinfo(conn)
	}
	if verbose {
		warnf("connected to %s %s (%s):\n", proto, addr,
			conn.RemoteAddr())
	}

	converse(conn, false)
}

// The need for this function is annoying. The net package should
// export this information, as well as what protocols are packet
// protocols and what protocols are stream protocols.
func isknownproto(s string) bool {
	switch s {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	case "unix", "unixgram", "unixpacket":
		// we can't currently support the ip / ipv4 / ipv6
		// protocol options that Dial et al does.

	case "ssl", "tls":
		// these our our special additions.

	default:
		return false
	}
	return true
}

// Guess the protocol given the port.
// We know a few TLS-based protocols.
// TODO: implement this better.
func guessproto(port string, defproto string) string {
	switch port {
	case "https", "smtps", "ldaps", "imaps", "pop3s", "443", "465", "636", "993", "995":
		return "tls"
	default:
		return defproto
	}
}

//
// It would be nice if this didn't have to be hardcoded. See above.
func listprotos() {
	fmt.Println(`call: known protocols:
  tcp tcp4 tcp6 unix unixpacket		[stream protocols, more or less]
  udp udp4 udp6 unixgram		[datagram protocols]

  ssl tls		[TLS/SSL with certificate verification]

 TLS/SSL does not support -l.
 unix* protocols take a filename as their address; for -l, it shouldn't
 already exist.`)
}

//
func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [-h] [-lHINPRTqv] [-b address] [-B bufsize] [-C num] [proto] {address | host port}\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  address is host:port for appropriate protocols.")
	fmt.Fprintln(os.Stderr, "  default proto is tcp. See -P for protocols. -l listens instead of calls.")
}

//
//
func main() {
	proto := "tcp"
	var addr, laddr string
	var tmout time.Duration
	var lstn = flag.Bool("l", false, "listen for connections instead of make them")
	var pprotos = flag.Bool("P", false, "just print our known protocols")
	flag.BoolVar(&quiet, "q", false, "be quieter in some situations")
	flag.BoolVar(&verbose, "v", false, "be more verbose in some situations")
	flag.BoolVar(&reporttls, "T", false, "report TLS connection information")
	flag.IntVar(&conns, "C", 0, "if non-zero, -l only listens for this many `connections` then exits")
	flag.BoolVar(&dgramhex, "H", false, "for -l, print received UDP/Unix datagrams as hex bytes")
	flag.BoolVar(&recvonly, "R", false, "for -l, only receive datagrams, do not try to send stdin")
	flag.StringVar(&laddr, "b", "", "make the call from this local `address` (can be just an IP or hostname)")
	flag.IntVar(&bufsize, "B", DEFAULTNETBUF, "the buffer size for (network) IO, in `bytes`")
	flag.BoolVar(&convnl, "N", false, "convert newlines in the input to CR NL")
	flag.BoolVar(&addnl, "L", false, "for -l, append a newline to the received datagrams if they lack them")
	flag.BoolVar(&insec, "I", false, "don't verify the server TLS certificate for TLS connections")

	// I really wish we could specify a default unit for duration parsing
	// so people did not have to say '3s' for '3 seconds'.
	flag.DurationVar(&tmout, "t", 0, "connection timeout for the call if any; use eg '1s' for seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] [protocol] {host port | address}\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n The default protocol is 'tcp'.")
		fmt.Fprintln(os.Stderr, " The address may be given as host:port for IP-based protocols.")
	}

	flag.Parse()

	if *pprotos {
		listprotos()
		return
	}

	switch narg := flag.NArg(); {
	case narg > 3 || narg == 0:
		usage()
		return

	case narg == 3:
		proto = flag.Arg(0)
		addr = flag.Arg(1) + ":" + flag.Arg(2)
	case narg == 2:
		// Try to avoid mistaking not-supported net.Dial protocols
		// for hostnames.
		// TODO: do this better. Would it kill the net package
		// to export some validation routines for us?
		pt := flag.Arg(0)
		if pt == "ip" || pt == "ipv4" || pt == "ipv6" {
			warnf("protocol %s is not supported\n", pt)
			return
		}

		// If arg[0] is a known protocol or arg[1] contains a :
		// we assume that we have 'proto address'; otherwise we
		// assume we have a two-argument 'host port' thing.
		if isknownproto(flag.Arg(0)) || strings.Contains(flag.Arg(1), ":") {
			proto = flag.Arg(0)
			addr = flag.Arg(1)
		} else {
			proto = guessproto(flag.Arg(1), proto)
			addr = flag.Arg(0) + ":" + flag.Arg(1)
		}
	case narg == 1:
		// By extension with the two argument case, we attempt
		// to guess the protocol based on the port. Generally
		// it's going to be there (as the last :, given IPv6
		// addresses).
		// This will do odd things in combination with -l for
		// a TLS-based service, but then you probably want to
		// be explicit there anyway. Or at least that's my
		// excuse.
		addr = flag.Arg(0)
		n := strings.LastIndexByte(addr, ':')
		if n != -1 {
			proto = guessproto(addr[n+1:], proto)
		}
	}

	if !isknownproto(proto) {
		warnf("protocol %s is not recognized and/or supported\n",
			proto)
		return
	}

	if *lstn {
		// It is annoying that we have to burn in the knowledge
		// of what is a packet protocol and what is a stream
		// protocol. See prior grumbling.
		switch proto {
		case "udp", "udp4", "udp6", "unixgram":
			listenpacket(proto, addr)
		case "ssl", "tls":
			// We might as well be friendly.
			warnf("protocol %s not supported for listening\n",
				proto)
			return
		default:
			listen(proto, addr)
		}
	} else {
		// Calling things doesn't depend on datagram versus stream
		// protocols; net.Dial() makes it all work.
		// (Don't ask me how unixgram works one way and not the
		// other.)
		call(proto, addr, laddr, tmout)
	}
}
