package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/NNdroid/udp_custom/tunnel"
)

type StunProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SSHAddr           string `json:"sshAddr"`
	User              string `json:"user"`
	Pass              string `json:"pass"`
	AuthType          string `json:"authType"`
	TunnelType        string `json:"tunnelType"`
	ProxyAddr         string `json:"proxyAddr"`
	CustomHost        string `json:"customHost"`
	ServerName        string `json:"serverName"`
	CustomPath        string `json:"customPath"`
	EnableCustomPath  bool   `json:"enableCustomPath"`
	ProxyAuthRequired bool   `json:"proxyAuthRequired"`
	UDPCustomPsk      string `json:"udpCustomPsk"`
	UDPCustomMagic    string `json:"udpCustomMagic"`
	NoisePublicKey    string `json:"noisePublicKey"`
}

func GenerateUDPCustomURI(host, port, password, magic, pubKey, remark, pin string) string {
	pubHex, pubB64 := "", ""
	if pubKey != "" {
		if pk, err := tunnel.ParseNoiseKey(pubKey); err == nil {
			pubHex, pubB64 = tunnel.FormatNoiseKey(pk)
		}
	}
	rawPub := pubB64
	if rawPub == "" {
		rawPub = pubHex
	}

	serverAddr := fmt.Sprintf("%s:%s", host, port)
	if host == "" || host == "0.0.0.0" || host == ":" {
		serverAddr = "YOUR_SERVER_IP:" + port
	}

	name := remark
	if name == "" {
		name = "UDPCustom - " + serverAddr
	}

	// 1. Official Stun Sharing Link (stun://, encrypted like the Stun Android / TV client)
	prof := StunProfile{
		Name:           name,
		SSHAddr:        "127.0.0.1:22",
		User:           "root",
		AuthType:       "password",
		TunnelType:     "udp_custom",
		ProxyAddr:      serverAddr,
		UDPCustomPsk:   password,
		UDPCustomMagic: magic,
		NoisePublicKey: rawPub,
	}
	profJSON, _ := json.Marshal(prof)
	stunURI, usedPin, err := encryptStunURI(profJSON, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to encrypt share URI (%v); falling back to plaintext stun://.\n", err)
		stunURI = "stun://" + base64.StdEncoding.EncodeToString(profJSON)
	}

	// 2. Direct Protocol URI (plaintext, for non-Stun clients)
	protoURI := fmt.Sprintf("udpc://%s?magic=%s", serverAddr, magic)
	if password != "" {
		protoURI += "&psk=" + password
	}
	if rawPub != "" {
		protoURI += "&pubkey=" + rawPub
	}

	fmt.Printf("\n[1] Official Stun Sharing Link (stun://, encrypted):\n  %s\n", stunURI)
	if pin == "" {
		fmt.Printf("\n[PIN] %s  <- share this PIN with the importer (Stun App will ask for it)\n", usedPin)
	} else {
		fmt.Printf("\n[PIN] (using provided PIN)\n")
	}
	fmt.Printf("\n[2] Direct Protocol URI (plaintext):\n  %s\n\n", protoURI)

	return stunURI
}

// PrintTerminalQR renders text as a scannable QR code directly in the terminal
// using Unicode half-block characters (two module rows per text line, so even
// large QR versions stay compact). It degrades gracefully to plain text when
// the payload exceeds QR capacity.
func PrintTerminalQR(text string) {
	fmt.Println("Scan in Stun Android / TV App (Supports stun:// and direct scan):")
	qr, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		// Payload too large for a QR code — fall back to the raw link.
		fmt.Printf("\n  %s\n  (payload too large to render as QR code — copy the link above instead)\n\n", text)
		return
	}
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Println("  (If the QR does not scan on a dark terminal theme, copy the link above.)")
}
