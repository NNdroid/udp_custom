package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/NNdroid/udp_custom/tunnel"
)

var Version = "2.0.0"

type Config struct {
	// Mode selects what this binary does: "server" (default, also when absent)
	// or "client". See config.server.json / config.client.json.
	Mode string `json:"mode"`

	// Sockets is client-only: number of local UDP sockets used for n:n port
	// spreading (1 = single socket). 0 = 1.
	Sockets int `json:"sockets"`

	// Paths is client-only: how many DISTINCT remote ports the client randomly
	// picks from the server's port range for the whole session (the client is
	// the source of truth; the server mirrors each one back via origdst). 0 =
	// spread every packet across the ENTIRE range (original behaviour). 32 is
	// a good fixed-subset size.
	Paths int `json:"paths"`

	// PubKey is client-only: the SERVER's Noise static public key. When set,
	// the client performs a Noise_NK handshake and encrypts all data.
	PubKey string `json:"pubkey"`

	// Server is client-only: remote udp_custom server address, "host:port" or
	// "host:port-range" for port spreading.
	Server string `json:"server"`

	Listen    string   `json:"listen"`     // UDP listen address / port the server binds, e.g. ":36712". The SINGLE port; a firewall DNAT redirects the client port range onto it.
	Host      string   `json:"host"`       // Server public IP / domain (used by gen-uri to build the sharing link)
	PortRange string   `json:"port_range"` // FIRST-CLASS server port range, e.g. "25000-26000" (host optional). The firewall DNATs this whole range onto 'listen'. Used at runtime to validate incoming origdst ports and as the default --range for gen-nftables/gen-iptables.
	Target    string   `json:"target"`     // Server: DEFAULT target service (e.g. "tcp://127.0.0.1:22"). Client: target requested in the handshake ("" = server default); must pass the server's allowed_targets filter.
	Passwords []string `json:"passwords"`  // List of pre-shared keys
	Magic     string   `json:"magic"`      // 4-byte protocol magic
	PrivKey   string   `json:"privkey"`    // Static private key for Noise encryption (Hex / Base64)
	LogLevel  string   `json:"log_level"`  // debug, info, warn, error

	// AllowedTargets (server) gates client-requested per-session targets with
	// '*'/'?' wildcards, e.g. "tcp://127.0.0.1:*". Empty = only the default
	// 'target'. See tunnel.ServerConfig.AllowedTargets.
	AllowedTargets []string `json:"allowed_targets"`

	// ReceiveSockets (server, Linux only) opens N SO_REUSEPORT UDP sockets on
	// 'listen', each with its own read goroutine, scaling packet intake across
	// cores. 0/1 = single socket. Other platforms clamp to 1.
	ReceiveSockets int `json:"receive_sockets"`

	// OrigDst enables IP_RECVORIGDSTADDR (Linux only). REQUIRED whenever the
	// client spreads across more than one destination port: it lets the server
	// recover the client's original destination port and reply from it, which
	// is what makes a CGNAT accept the reply. nil (field absent) = enabled;
	// set false only for a single-port (no spreading) deployment.
	OrigDst *bool `json:"origdst"`

	// SendSockMax caps the LRU cache of per-port reply sockets (one socket per
	// client destination port in flight). Past the limit live sockets are
	// evicted. 0 = 512.
	SendSockMax int `json:"sendsock_max"`

	// SendWindow caps the number of DATA frames in flight awaiting an ACK
	// before the target read loop blocks (backpressure). 0 = 256.
	SendWindow int `json:"send_window"`
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := struct {
		*Alias
		RawPasswords interface{} `json:"passwords"`
		RawPassword  string      `json:"password"`
		RawToken     interface{} `json:"token"`
		RawAuthToken interface{} `json:"auth_token"`
		RawPSK       interface{} `json:"psk"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	collect := func(v interface{}) {
		if v == nil {
			return
		}
		switch val := v.(type) {
		case string:
			for _, s := range strings.Split(val, ",") {
				trimmed := strings.TrimSpace(s)
				if trimmed != "" {
					c.Passwords = append(c.Passwords, trimmed)
				}
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					trimmed := strings.TrimSpace(s)
					if trimmed != "" {
						c.Passwords = append(c.Passwords, trimmed)
					}
				}
			}
		}
	}

	collect(aux.RawPasswords)
	collect(aux.RawToken)
	collect(aux.RawAuthToken)
	collect(aux.RawPSK)
	if aux.RawPassword != "" {
		c.Passwords = append(c.Passwords, strings.TrimSpace(aux.RawPassword))
	}

	return nil
}

// loadConfigFile reads and parses a JSON config file.
//
// This is the ONLY source of configuration. Per project convention there is no
// environment-variable override and no implicit default file name: whatever the
// file passed with -c says is what the server runs with. That keeps a running
// deployment fully described by a single artefact.
func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-c" || os.Args[1] == "--config" || strings.HasPrefix(os.Args[1], "-c=") || strings.HasPrefix(os.Args[1], "--config=")) {
		// No implicit "config.json" fallback: the path must be given explicitly.
		confPath := ""
		if strings.Contains(os.Args[1], "=") {
			confPath = strings.TrimSpace(strings.SplitN(os.Args[1], "=", 2)[1])
		} else if len(os.Args) > 2 {
			confPath = strings.TrimSpace(os.Args[2])
		}
		if confPath == "" {
			fmt.Fprintf(os.Stderr, "-c requires a configuration file path\n\n")
			printUsage()
			os.Exit(1)
		}
		runFromConfig(confPath)
		return
	}

	if len(os.Args) > 1 && (os.Args[1] == "gen-keys" || os.Args[1] == "gen-uri" || os.Args[1] == "gen-systemd" || os.Args[1] == "gen-iptables" || os.Args[1] == "gen-nftables" || os.Args[1] == "version" || os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help") {
		handleUtilityCommands(os.Args[1:])
		return
	}

	// -c is the only supported configuration source. There is deliberately no
	// environment-variable fallback and no search for a default file name: a
	// running server must be fully described by the one file passed with -c.
	fmt.Fprintf(os.Stderr, "udp_custom requires a configuration file: udp_custom -c config.json\n\n")
	printUsage()
	os.Exit(1)
}

// runClientMode boots the udp_custom client (config.json "mode":"client").
//
//	app ──tcp──► client(listen) ──udp_custom──► server ──tcp──► backend
func runClientMode(cfg *Config, magicStr, lvl string, sendWindow int) {
	serverAddr := strings.TrimSpace(cfg.Server)
	if serverAddr == "" {
		fmt.Fprintf(os.Stderr, "client mode: 'server' address is required\n")
		os.Exit(1)
	}
	if lvl == "" {
		lvl = "info"
	}

	clientCfg := tunnel.ClientConfig{
		ListenAddr: cfg.Listen,
		ServerAddr: serverAddr,
		Target:     cfg.Target,
		Passwords:  cfg.Passwords,
		Magic:      parseMagicHeader(magicStr),
		LogLevel:   lvl,
		Sockets:    cfg.Sockets,
		Paths:      cfg.Paths,
		SendWindow: sendWindow,
	}

	// Optional Noise_NK encryption, keyed by the server's static public key.
	if pk := strings.TrimSpace(cfg.PubKey); pk != "" {
		pub, err := tunnel.ParseNoiseKey(pk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "client mode: invalid 'pubkey': %v\n", err)
			os.Exit(1)
		}
		clientCfg.ServerPub = pub
	}

	cli, err := tunnel.NewClient(clientCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start client: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("Shutting down udp_custom client gracefully...")
		cli.Close()
	}()

	if err := cli.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Client runtime error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("udp_custom client stopped.")
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}

	lvl := cfg.LogLevel
	if lvl == "" {
		lvl = "info"
	}

	listen := cfg.Listen
	if listen == "" {
		listen = ":36712"
	}
	target := cfg.Target
	if target == "" {
		target = "tcp://127.0.0.1:22"
	}
	m := cfg.Magic
	if m == "" {
		m = "UDPC"
	}
	magicVal := parseMagicHeader(m)

	origDst := true
	if cfg.OrigDst != nil {
		origDst = *cfg.OrigDst
	}
	sendSockMax := cfg.SendSockMax
	sendWindow := cfg.SendWindow

	// Client mode: same binary, different role — see client.go. Without this
	// branch, "mode":"client" (config.client.json) would silently be ignored
	// and the binary would boot as a server on the client's 'listen' port.
	if strings.EqualFold(strings.TrimSpace(cfg.Mode), "client") {
		runClientMode(cfg, m, lvl, sendWindow)
		return
	}

	// 'port_range' is the single source of truth for the client port range and
	// the firewall DNAT. The three classic port-spreading misconfigurations
	// had no detector anywhere before; check them at boot now.
	validatePortRange(cfg.PortRange, listen, origDst, sendSockMax)

	srvCfg := tunnel.ServerConfig{
		ListenAddr:     listen,
		TargetAddr:     target,
		Passwords:      cfg.Passwords,
		Magic:          magicVal,
		PrivateKey:     cfg.PrivKey,
		LogLevel:       lvl,
		OrigDst:        origDst,
		SendSockMax:    sendSockMax,
		SendWindow:     sendWindow,
		PortRange:      cfg.PortRange,
		AllowedTargets: cfg.AllowedTargets,
		ReceiveSockets: cfg.ReceiveSockets,
	}

	srv, err := tunnel.NewServer(srvCfg)
	if err != nil {
		log.Fatalf("Failed to initialize server from config: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down udp_custom server gracefully...")
		srv.Close()
		// Do NOT os.Exit here: closing the listening socket makes Start()
		// return, so main unwinds normally and defers run.
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("Server runtime error: %v", err)
	}
	log.Println("udp_custom server stopped.")
}

func handleUtilityCommands(args []string) {
	switch args[0] {
	case "gen-keys":
		kp, err := tunnel.GenerateNoiseKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
			os.Exit(1)
		}
		privHex, privB64 := tunnel.FormatNoiseKey(kp.PrivateKey)
		pubHex, pubB64 := tunnel.FormatNoiseKey(kp.PublicKey)
		fmt.Println("=== 🔑 Noise Curve25519 Keypair ===")
		fmt.Printf("Server Private Key (privkey):\n  Hex:    %s\n  Base64: %s\n\n", privHex, privB64)
		fmt.Printf("Client Public Key (pubkey):\n  Hex:    %s\n  Base64: %s\n", pubHex, pubB64)
	case "gen-uri":
		runGenURI(args[1:])
	case "gen-systemd":
		generateSystemd()
	case "gen-iptables":
		runGenIptables(args[1:])
	case "gen-nftables":
		runGenNftables(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("udp_custom version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	}
}

// validatePortRange checks the configured client port range against the values
// that DO affect the running server. It is warn-only: a questionable range must
// never stop an otherwise healthy server from booting. The three failure modes
// it catches are all silent in production — they show up only as heavy
// retransmission, which is indistinguishable from a bad link.
func validatePortRange(portRange, listen string, origDst bool, sendSockMax int) {
	pr := tunnel.PortRangeOf(portRange)
	if pr == nil {
		// No range configured — a single-port (no spreading) deployment,
		// nothing to validate.
		return
	}

	// Tell the operator what the server now expects and that the firewall must
	// DNAT this range onto 'listen'.
	log.Printf("📣 [port_range] server expects client packets on port range %s (%d ports); ensure the firewall DNATs this range onto 'listen'",
		pr.String(), pr.Total())

	if pr.Total() == 1 {
		// A single port means no spreading at all; a valid deployment where
		// none of the checks below apply.
		return
	}

	// (1) The reply-socket pool needs one cached socket per range port. Past
	// the LRU limit every packet evicts a live socket and re-binds, which
	// costs a syscall pair per packet and churns source ports.
	limit := sendSockMax
	if limit <= 0 {
		limit = tunnel.DefaultSendSockMax
	}
	if pr.Total() > limit {
		log.Printf("⚠️  [port_range] %d ports exceeds sendsock_max=%d — the reply-socket cache will evict on nearly every packet; raise sendsock_max or shrink the range",
			pr.Total(), limit)
	}

	// (2) origdst mirrors each packet's original destination port back to the
	// client. Without it every reply leaves from the 'listen' port, and any
	// NAT that keys on the source port drops it.
	if !origDst {
		log.Printf("⚠️  [port_range] a %d-port range is configured but origdst=false — every reply would leave from the 'listen' port and strict NATs drop those; set \"origdst\": true",
			pr.Total())
	}

	// (3) The listen port sitting inside the range is the nastiest one: those
	// packets bypass the firewall DNAT and reach the socket directly, so a
	// broken DNAT still looks "slow but working" and the real fault stays
	// hidden.
	if _, lp, e := net.SplitHostPort(listen); e == nil {
		if p, ce := strconv.Atoi(lp); ce == nil && pr.Contains(p) {
			log.Printf("⚠️  [port_range] the range CONTAINS the listen port %d — packets sent there skip the firewall DNAT and hit this socket directly, which masks a broken DNAT as heavy retransmission; exclude %d from the range",
				p, p)
		}
	}
}

func runGenURI(args []string) {
	fs := flag.NewFlagSet("gen-uri", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	host := fs.String("host", "", "Server public IP / domain")
	port := fs.String("port", "", "Server UDP port")
	password := fs.String("p", "", "Password / PSK")
	magic := fs.String("m", "", "Magic header")
	pubKey := fs.String("pubkey", "", "Server Noise public key")
	remark := fs.String("name", "", "Node remark name")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// Values from the config file are seeded first, then any explicit command
	// line flag overrides the corresponding field.
	if *cfgPath != "" {
		if fileCfg, err := loadConfigFile(*cfgPath); err == nil {
			// 'host' carries the server's public address for the client
			// config; 'port_range' carries the client-facing UDP port range.
			if *host == "" && fileCfg.Host != "" {
				*host = fileCfg.Host
			}
			if *port == "" && fileCfg.PortRange != "" {
				if ports, pe := tunnel.ParsePortRangeSpec(fileCfg.PortRange); pe == nil {
					*port = tunnel.FormatPortList(ports)
				}
			}
			if *port == "" && fileCfg.Listen != "" {
				if _, p, err := net.SplitHostPort(fileCfg.Listen); err == nil {
					*port = p
				}
			}
			if *password == "" && len(fileCfg.Passwords) > 0 {
				*password = fileCfg.Passwords[0]
			}
			if *magic == "" && fileCfg.Magic != "" {
				*magic = fileCfg.Magic
			}
			if *pubKey == "" && fileCfg.PubKey != "" {
				*pubKey = fileCfg.PubKey
			}
			if *pubKey == "" && fileCfg.PrivKey != "" {
				if kp, pe := tunnel.ParseNoiseKey(fileCfg.PrivKey); pe == nil {
					_, pubB64 := tunnel.FormatNoiseKey(kp)
					*pubKey = pubB64
				}
			}
		}
	}

	// Built-in fallbacks for anything still unset.
	if *host == "" {
		*host = "your-server-ip"
	}
	if *port == "" {
		*port = "36712"
	}
	if *magic == "" {
		*magic = "UDPC"
	}
	if *remark == "" {
		*remark = "UDP Custom Node"
	}

	uri := GenerateUDPCustomURI(*host, *port, *password, *magic, *pubKey, *remark, *pin)
	fmt.Printf("=== 📱 udp_custom Sharing URI (encrypted stun://) ===\n\n%s\n", uri)
	PrintTerminalQR(uri)
}

func parseMagicHeader(m string) uint32 {
	if len(m) == 4 {
		return uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
	}
	return 0x55445043 // "UDPC"
}

func printUsage() {
	fmt.Println("Usage: udp_custom -c <config.json>")
	fmt.Println()
	fmt.Println("  -c is REQUIRED and is the only supported configuration source.")
	fmt.Println("  There are no environment variables and no default file name: the")
	fmt.Println("  server runs exactly as the given JSON file describes.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c <file>, --config <file>, -c=<file>, --config=<file>")
	fmt.Println("                   Path to the JSON configuration file (required)")
	fmt.Println()
	fmt.Println("Utility Commands:")
	fmt.Println("  gen-keys         Generate Curve25519 keypair for Noise encryption")
	fmt.Println("  gen-uri          Generate Stun client sharing URI link (encrypted stun://, PIN-protected) & QR Code")
	fmt.Println("  gen-systemd      Generate Linux systemd service unit")
	fmt.Println("  gen-iptables     Generate iptables REDIRECT rules for a UDP port range (--range / --port)")
	fmt.Println("  gen-nftables     Generate nftables DNAT rules for a UDP port range (--range / --to)")
	fmt.Println("  version          Show version information")
	fmt.Println("  help             Show help message")
}
