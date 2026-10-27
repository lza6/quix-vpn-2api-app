// quixsocks: local SOCKS5 front over QuixVPN WireGuard tunnels.
// Each harvested profile gets its own userspace WG netstack device; a local
// SOCKS5 listener forwards connections through the tunnel (remote DNS).
// Usage: quixsocks.exe <profiles.json> <listenBasePort> [hostFilter]
//   node i -> 127.0.0.1:(basePort+i), SOCKS5, no auth. Health via CONNECT latency.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Profile struct {
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	Conf     string `json:"conf"`
}

type tunnel struct {
	prof  Profile
	port  int
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	ok    atomic.Bool
	latMs atomic.Int64
}

func hexKey(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

func parseConf(conf string) (priv, peerPub, psk, addr string) {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PrivateKey = "):
			priv = strings.TrimPrefix(line, "PrivateKey = ")
		case strings.HasPrefix(line, "PublicKey = "):
			peerPub = strings.TrimPrefix(line, "PublicKey = ")
		case strings.HasPrefix(line, "PresharedKey = "):
			psk = strings.TrimPrefix(line, "PresharedKey = ")
		case strings.HasPrefix(line, "Address = "):
			addr = strings.TrimPrefix(line, "Address = ")
		}
	}
	return
}

func buildTunnel(p Profile) (*tunnel, error) {
	priv, peerPub, psk, addr := parseConf(p.Conf)
	if priv == "" || peerPub == "" || addr == "" {
		return nil, fmt.Errorf("bad conf")
	}
	ip := netip.MustParseAddr(strings.Split(addr, "/")[0])
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ip},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")},
		1280)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", hexKey(priv))); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\npreshared_key=%s\n",
		hexKey(peerPub), p.Endpoint, hexKey(psk))); err != nil {
		dev.Close()
		return nil, err
	}
	t := &tunnel{prof: p, dial: tnet.DialContext}
	return t, nil
}

func (t *tunnel) probe() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=text", nil)
	tr := &http.Client{Transport: &http.Transport{DialContext: t.dial}}
	t0 := time.Now()
	resp, err := tr.Do(req)
	if err != nil {
		t.ok.Store(false)
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	t.latMs.Store(time.Since(t0).Milliseconds())
	t.ok.Store(true)
	return true
}

// socks5: minimal no-auth CONNECT handler (RFC 1928 subset), IPv4/domain only.
func (t *tunnel) serveSocks(c net.Conn) {
	defer c.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 5 {
		return
	}
	if head[1] > 0 { // consume methods list
		m := make([]byte, head[1])
		if _, err := io.ReadFull(c, m); err != nil {
			return
		}
	}
	c.Write([]byte{5, 0}) // no auth
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var target string
	switch req[3] {
	case 1: // ipv4
		b := make([]byte, 6)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		target = net.IP(b[:4]).String() + ":" + strconv.Itoa(int(b[4])<<8|int(b[5]))
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(c, d); err != nil {
			return
		}
		po := make([]byte, 2)
		if _, err := io.ReadFull(c, po); err != nil {
			return
		}
		target = string(d) + ":" + strconv.Itoa(int(po[0])<<8|int(po[1]))
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // addr type not supported
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	up, err := t.dial(ctx, "tcp", target)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <profiles.json> <basePort> [hostFilter]", os.Args[0])
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var profs []Profile
	if err := json.Unmarshal(raw, &profs); err != nil {
		log.Fatal(err)
	}
	base, _ := strconv.Atoi(os.Args[2])
	filter := ""
	if len(os.Args) > 3 {
		filter = os.Args[3]
	}
	port := base
	var ts []*tunnel
	for _, p := range profs {
		if filter != "" && !strings.Contains(p.Host, filter) {
			continue
		}
		t, err := buildTunnel(p)
		if err != nil {
			log.Printf("[skip] %s: %v", p.Host, err)
			continue
		}
		t.port = port
		port++
		ts = append(ts, t)
	}
	// probes + listeners
	for _, t := range ts {
		go func(t *tunnel) {
			if t.probe() {
				log.Printf("[up]   %s:%d -> %s (%dms)", "127.0.0.1", t.port, t.prof.Host, t.latMs.Load())
			} else {
				log.Printf("[down] %s (socks still listening on %d)", t.prof.Host, t.port)
			}
			go func(t *tunnel) {
				for range time.Tick(10 * time.Minute) {
					t.probe()
				}
			}(t)
		}(t)
		go func(t *tunnel) {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", t.port))
			if err != nil {
				log.Printf("[listen-err] %d: %v", t.port, err)
				return
			}
			log.Printf("[socks] 127.0.0.1:%d => %s (%s)", t.port, t.prof.Host, t.prof.Endpoint)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go t.serveSocks(c)
			}
		}(t)
	}
	// status endpoint
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString("[")
		for i, t := range ts {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"host":%q,"socks":"127.0.0.1:%d","ok":%t,"latency_ms":%d}`,
				t.prof.Host, t.port, t.ok.Load(), t.latMs.Load())
		}
		sb.WriteString("]")
		w.Write([]byte(sb.String()))
	})
	go http.ListenAndServe("127.0.0.1:8950", nil)
	log.Printf("ready: %d tunnels, status http://127.0.0.1:8950/status", len(ts))
	select {}
}
