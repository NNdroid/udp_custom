//go:build ignore

// Build this same probe against two repository revisions to check a real
// mixed-version handshake and stream: go build -o interop scripts/interop_probe.go.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NNdroid/udp_custom/tunnel"
)

const probePSK = "mixed-version-validation-secret"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: interop server [noise] | client address [public-key]")
	}
	if os.Args[1] == "server" {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		cfg := tunnel.ServerConfig{TargetAddr: "tcp://echo:1", Passwords: []string{probePSK}, Logger: tunnel.Nop}
		pub := "none"
		if len(os.Args) > 2 && os.Args[2] == "noise" {
			kp, err := tunnel.GenerateNoiseKeyPair()
			if err != nil {
				return err
			}
			cfg.PrivateKey = fmt.Sprintf("%x", kp.PrivateKey)
			pub = fmt.Sprintf("%x", kp.PublicKey)
		}
		srv, err := tunnel.NewServerWithConn(cfg, conn, func(context.Context, uint32, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
			return a, nil
		})
		if err != nil {
			conn.Close()
			return err
		}
		defer srv.Close()
		fmt.Println(conn.LocalAddr().String(), pub)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
		defer signal.Stop(stop)
		finished := make(chan error, 1)
		go func() { finished <- srv.Start() }()
		select {
		case <-stop:
			srv.Close()
			return nil
		case err := <-finished:
			return err
		}
	}
	if len(os.Args) < 3 {
		return fmt.Errorf("client address required")
	}
	off := false
	cfg := tunnel.ClientConfig{ServerAddr: os.Args[2], Passwords: []string{probePSK}, Logger: tunnel.Nop, MtuProbe: &off}
	if len(os.Args) > 3 && os.Args[3] != "none" {
		var err error
		cfg.ServerPub, err = tunnel.ParseNoiseKey(os.Args[3])
		if err != nil {
			return err
		}
	}
	c, err := tunnel.NewClient(cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.DialTunnel(ctx, tunnel.DialOptions{})
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	want := make([]byte, 64<<10)
	for i := range want {
		want[i] = byte((i*13 + i/127) % 251)
	}
	writeErr := make(chan error, 1)
	go func() { _, err := conn.Write(want); writeErr <- err }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if err := <-writeErr; err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("mixed-version stream corruption")
	}
	fmt.Printf("verified %d bytes\n", len(got))
	return nil
}
