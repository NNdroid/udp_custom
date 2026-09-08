package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/NNdroid/udp_custom/tunnel"
)

// generateSystemd emits a systemd unit. udp_custom is config-file driven
// (the per-parameter CLI flags were removed), so the unit always launches
// via `-c /etc/udp_custom/config.json`.
func generateSystemd() {
	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/udp_custom"
	}

	execLine := fmt.Sprintf("%s -c /etc/udp_custom/config.json", execPath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=UDPCustom Server (SSH over UDP Tunnel)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/udp_custom
ExecStart=%s
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, execLine)

	fmt.Println("=== Systemd Service Configuration ===")
	fmt.Println("Save to: /etc/systemd/system/udp_custom.service")
	fmt.Println("----------------------------------------")
	fmt.Print(serviceContent)
	fmt.Println("----------------------------------------")
	fmt.Println("Place /etc/udp_custom/config.json (e.g.):")
	fmt.Println(`{
  "listen": ":36712",
  "target": "tcp://127.0.0.1:22",
  "passwords": ["your-strong-psk"],
  "magic": "UDPC",
  "log_level": "info"
}`)
	fmt.Println("----------------------------------------")
	fmt.Println("Commands to activate:")
	fmt.Println("  sudo systemctl daemon-reload")
	fmt.Println("  sudo systemctl enable --now udp_custom")
	fmt.Println("  sudo systemctl status udp_custom")
}

// dnatDportsArg splits range tokens into chunks of at most 15 entries, which is
// the limit of a single iptables `-m multiport --dports` match.
func dnatDportsArg(tokens []string) []string {
	const maxMultiport = 15
	var args []string
	for i := 0; i < len(tokens); i += maxMultiport {
		end := i + maxMultiport
		if end > len(tokens) {
			end = len(tokens)
		}
		args = append(args, strings.Join(tokens[i:end], ","))
	}
	return args
}

// intervalTokens renders the tunnel.PortRange as range tokens using sep as the
// range separator. iptables multiport wants ":" (e.g. "1024:23000"); nftables
// wants "-" (e.g. "1024-23000").
func intervalTokens(pr *tunnel.PortRange, sep string) []string {
	if pr == nil {
		return nil
	}
	var out []string
	for _, iv := range pr.Intervals() {
		if iv.Lo == iv.Hi {
			out = append(out, strconv.Itoa(iv.Lo))
		} else {
			out = append(out, fmt.Sprintf("%d%s%d", iv.Lo, sep, iv.Hi))
		}
	}
	return out
}

// generateIptables prints REDIRECT rules that send every incoming UDP packet on
// the configured port range to a single internal UDP port. The server keeps
// listening only on that internal port; the firewall does the spreading/merge.
func generateIptables(internalPort int, pr *tunnel.PortRange) {
	fmt.Println("=== Iptables Port Redirection / Hopping Rules ===")
	if pr == nil || pr.Total() == 0 {
		fmt.Printf("Redirecting all incoming UDP (ports 1000-65535) to local port %d:\n\n", internalPort)
		fmt.Printf("sudo iptables -t nat -A PREROUTING -p udp --dport 1000:65535 -j REDIRECT --to-ports %d\n", internalPort)
		return
	}
	fmt.Printf("Redirecting incoming UDP on port range %s to local port %d:\n\n", pr.String(), internalPort)
	for _, dports := range dnatDportsArg(intervalTokens(pr, ":")) {
		fmt.Printf("sudo iptables -t nat -A PREROUTING -p udp -m multiport --dports %s -j REDIRECT --to-ports %d\n", dports, internalPort)
	}
	fmt.Println("\n# Verify:  sudo iptables -t nat -L PREROUTING -n --line-numbers")
}

// generateNftables prints nftables rules that DNAT every incoming UDP packet on
// the configured port range onto an internal listen address, e.g.
// "127.0.0.1:36712". nftables handles arbitrary disjoint ranges natively.
func generateNftables(internalAddr string, pr *tunnel.PortRange) {
	fmt.Println("=== nftables Port Range DNAT Rules ===")
	if pr == nil || pr.Total() == 0 {
		fmt.Println("No port range provided.")
		return
	}
	set := "{" + strings.Join(intervalTokens(pr, "-"), ", ") + "}"
	fmt.Printf("Redirect incoming UDP on port range %s to %s:\n\n", pr.String(), internalAddr)
	fmt.Println("sudo nft add table ip udpc")
	fmt.Println("sudo nft 'add chain ip udpc prerouting { type nat hook prerouting priority dstnat; }'")
	fmt.Printf("sudo nft add rule ip udpc prerouting ip protocol udp th dport %s dnat to %s\n", set, internalAddr)
	fmt.Println("\n# Persist: sudo nft list ruleset > /etc/nftables.conf   (and enable nftables.service)")
	fmt.Println("# Flush:   sudo nft delete table ip udpc")
	fmt.Println()
	fmt.Println("# NOTE — return path: the server mirrors each packet's original destination")
	fmt.Println("# port itself (config: origdst), so replies never rely on conntrack's")
	fmt.Println("# reverse DNAT.")
	fmt.Println("#")
	fmt.Println("# NOTE — inbound path with a 127.0.0.1 target: the kernel treats 127.0.0.0/8")
	fmt.Println("# as martian on non-loopback interfaces, so a packet arriving on a physical")
	fmt.Println("# NIC and DNATed to 127.0.0.1 is DROPPED unless route_localnet is enabled:")
	fmt.Println("#   sudo sysctl -w net.ipv4.conf.all.route_localnet=1")
	fmt.Println("#   echo 'net.ipv4.conf.all.route_localnet=1' > /etc/sysctl.d/99-udpc.conf")
	fmt.Println("# Symptom when it is missing: the handshake succeeds on the primary port")
	fmt.Println("# while every spread packet vanishes, i.e. a huge retransmission count.")
	fmt.Println("# Simpler alternative: DNAT to the NIC address instead (--to <nic-ip>:PORT)")
	fmt.Println("# and keep the server on \"listen\": \":PORT\" — no sysctl needed.")
	fmt.Println("#")
	fmt.Println("# If origdst is unavailable, the range will NOT work; the server logs")
	fmt.Println("# \"⚠️ Could not enable IP_RECVORIGDSTADDR\" at startup.")
}

func atoiPort(s string) int {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 36712
	}
	return p
}

// resolveRangeSpec reads --range / -c and returns the parsed tunnel.PortRange.
// Resolution order: explicit --range > config 'port_range'.
func resolveRangeSpec(args []string, fs *flag.FlagSet) (pr *tunnel.PortRange) {
	rangeSpec := fs.Lookup("range").Value.String()
	cfgPath := fs.Lookup("c").Value.String()
	if rangeSpec == "" && cfgPath != "" {
		if fileCfg, e := loadConfigFile(cfgPath); e == nil && fileCfg.PortRange != "" {
			rangeSpec = fileCfg.PortRange
		}
	}
	if rangeSpec == "" {
		return nil
	}
	ports, err := tunnel.ParsePortRangeSpec(rangeSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --range %q: %v\n", rangeSpec, err)
		os.Exit(1)
	}
	pr, err = tunnel.NewPortRange(ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid range: %v\n", err)
		os.Exit(1)
	}
	return pr
}

func runGenIptables(args []string) {
	fs := flag.NewFlagSet("gen-iptables", flag.ContinueOnError)
	fs.String("c", "", "Path to configuration file")
	fs.String("range", "", "UDP destination port range, e.g. 25000-25499 (<= 512 ports is recommended)")
	internalPort := fs.String("port", "36712", "Internal UDP port the range is redirected to")
	_ = fs.Parse(args)

	pr := resolveRangeSpec(args, fs)
	port := atoiPort(*internalPort)
	if pr == nil {
		// Legacy full-range behaviour when nothing explicit is given.
		generateIptables(port, nil)
		return
	}
	generateIptables(port, pr)
}

func runGenNftables(args []string) {
	fs := flag.NewFlagSet("gen-nftables", flag.ContinueOnError)
	fs.String("c", "", "Path to configuration file")
	fs.String("range", "", "UDP destination port range, e.g. 25000-25499 (<= 512 ports is recommended)")
	to := fs.String("to", "127.0.0.1:36712", "Internal listen address the range is redirected to")
	_ = fs.Parse(args)

	pr := resolveRangeSpec(args, fs)
	internal := *to
	if internal == "127.0.0.1:36712" {
		if fileCfg, e := loadConfigFile(fs.Lookup("c").Value.String()); e == nil && fileCfg.Listen != "" {
			internal = fileCfg.Listen
		}
	}
	if pr == nil {
		fmt.Fprintln(os.Stderr, "No port range provided (use --range or set 'port_range' in config).")
		os.Exit(1)
	}
	generateNftables(internal, pr)
}
