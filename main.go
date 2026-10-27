// quixwg: bring up real WireGuard tunnels (userspace netstack, no TUN driver) using
// harvested QuixVPN profiles and verify data-plane by fetching https://api.ipify.org
// through each tunnel. A returned IP proves the credential works end to end.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
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

func hexKey(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

func testProfile(p Profile, timeout time.Duration) map[string]any {
	res := map[string]any{"host": p.Host, "endpoint": p.Endpoint}
	priv, peerPub, psk, addr := parseConf(p.Conf)
	if priv == "" || peerPub == "" || addr == "" {
		res["error"] = "conf parse failed"
		return res
	}
	ip := netip.MustParseAddr(strings.Split(addr, "/")[0])
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ip},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")},
		1280)
	if err != nil {
		res["error"] = "nettun: " + err.Error()
		return res
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))
	defer dev.Close()
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", hexKey(priv))); err != nil {
		res["error"] = "ipc priv: " + err.Error()
		return res
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\npreshared_key=%s\n",
		hexKey(peerPub), p.Endpoint, hexKey(psk))); err != nil {
		res["error"] = "ipc peer: " + err.Error()
		return res
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{DialContext: tnet.DialContext},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	target := "https://api.ipify.org?format=json"
	if v := os.Getenv("WG_TARGET_URL"); v != "" {
		target = v
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res["error"] = "tunnel http: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	res["egress_ip"] = strings.TrimSpace(string(buf[:n]))
	res["rtt_ms"] = float64(time.Since(t0).Milliseconds())
	res["valid"] = true
	return res
}

func main() {
	profPath := os.Args[1]
	filter := ""
	if len(os.Args) > 2 {
		filter = os.Args[2]
	}
	raw, _ := os.ReadFile(profPath)
	var profs []Profile
	if err := json.Unmarshal(raw, &profs); err != nil {
		fmt.Fprintln(os.Stderr, "bad profiles:", err)
		os.Exit(1)
	}
	var out []map[string]any
	ok := 0
	for _, p := range profs {
		if filter != "" && !strings.Contains(p.Host, filter) {
			continue
		}
		r := testProfile(p, 15*time.Second)
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
		out = append(out, r)
		if r["valid"] == true {
			ok++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d/%d tunnels verified\n", ok, len(out))
	json.Marshal(out) // keep import used
}
