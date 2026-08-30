package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// Android ShareCryptoUtils.isEncryptedPayload detects an envelope by the presence of v, s, i, c.
func TestEnvelopeShapeMatchesAndroid(t *testing.T) {
	plain := []byte(`{"name":"t","sshAddr":"1.2.3.4:22","tunnelType":"udp_custom"}`)
	uri, _, err := encryptStunURI(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "stun://") {
		t.Fatalf("expected stun:// prefix, got %s", uri)
	}
	payload := strings.TrimPrefix(uri, "stun://")
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "s", "i", "c"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("envelope missing key %q (Android needs v,s,i,c)", k)
		}
	}
	if env["v"].(float64) != 1 {
		t.Fatalf("v should be 1, got %v", env["v"])
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte(`{"name":"BigNode","privateKey":"` + strings.Repeat("A", 5000) + `"}`)
	uri, pin, err := encryptStunURI(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	// large payload should be gzipped (g == 1) to stay within QR capacity
	payload := strings.TrimPrefix(uri, "stun://")
	raw, _ := base64.StdEncoding.DecodeString(payload)
	var env map[string]any
	_ = json.Unmarshal(raw, &env)
	if int(env["g"].(float64)) != 1 {
		t.Fatalf("expected gzip flag g=1 for large payload, got %v", env["g"])
	}
	dec, err := decryptStunURI(uri, pin)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if dec != string(plain) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestDecryptWrongPinFails(t *testing.T) {
	uri, _, err := encryptStunURI([]byte("hello world"), "123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptStunURI(uri, "000000"); err == nil {
		t.Fatal("expected wrong-pin decryption to fail")
	}
}

func TestProvidedPinHonored(t *testing.T) {
	_, pin, err := encryptStunURI([]byte("x"), "654321")
	if err != nil {
		t.Fatal(err)
	}
	if pin != "654321" {
		t.Fatalf("provided PIN not honored: got %s", pin)
	}
}

// PBKDF2-HMAC-SHA256 known-answer test (RFC 7914 vector) to guarantee our key derivation
// matches Java PBKDF2WithHmacSHA256 for numeric PINs.
func TestPbkdf2MatchesRFC7914(t *testing.T) {
	out := pbkdf2.Key([]byte("passwd"), []byte("salt"), 1, 64, sha256.New)
	want, _ := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	if !equalBytes(out, want) {
		t.Fatalf("PBKDF2 mismatch:\n got %x\nwant %x", out, want)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
