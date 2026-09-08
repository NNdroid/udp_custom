package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Parameters MUST stay in sync with app.fjj.stun.util.ShareCryptoUtils (Stun Android / TV client).
const (
	shareSaltLen    = 16
	shareIvLen      = 12
	shareIterations = 10000
	shareKeyLen     = 32
	shareMaxSize    = 1 << 20
)

// shareEnvelope mirrors the JSON envelope produced by ShareCryptoUtils.encrypt:
//
//	{ "v": 1, "g": 0|1, "s": base64(salt), "i": base64(iv), "c": base64(ciphertext) }
//
// where "c" is AES-256-GCM ciphertext (auth tag appended) of the (optionally gzip'd) profile JSON.
type shareEnvelope struct {
	V int    `json:"v"`
	G int    `json:"g"`
	S string `json:"s"`
	I string `json:"i"`
	C string `json:"c"`
}

// GenerateRandomPIN returns a random 6-digit PIN string, identical to ShareCryptoUtils.generateRandomPIN.
// Numeric only, so UTF-8 and Java's char[] (ISO-8859-1) encodings are byte-identical during PBKDF2.
// It returns an error instead of silently degrading to a weak PIN.
func GenerateRandomPIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generate PIN: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func gzipData(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(b); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipData(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	plain, err := io.ReadAll(io.LimitReader(r, shareMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > shareMaxSize {
		return nil, fmt.Errorf("decompressed share profile is larger than %d bytes", shareMaxSize)
	}
	return plain, nil
}

// encryptStunURI encrypts plaintext profile JSON with the PIN and returns the full "stun://" URI
// understood by the Stun Android / TV client. If pin is empty, a random 6-digit PIN is generated
// and returned via usedPin so the caller can display it to the sharer.
func encryptStunURI(plainText []byte, pin string) (uri, usedPin string, err error) {
	usedPin = pin
	if usedPin == "" {
		usedPin, err = GenerateRandomPIN()
		if err != nil {
			return "", "", err
		}
	}

	// Optional gzip: only enable when it actually shrinks the plaintext (mirrors Android logic,
	// avoids exceeding QR code capacity for large nodes).
	raw := plainText
	if compressed, gzErr := gzipData(raw); gzErr == nil && len(compressed) < len(raw) {
		raw = compressed
	}

	salt := make([]byte, shareSaltLen)
	if _, err = rand.Read(salt); err != nil {
		return "", usedPin, fmt.Errorf("generate salt: %w", err)
	}
	iv := make([]byte, shareIvLen)
	if _, err = rand.Read(iv); err != nil {
		return "", usedPin, fmt.Errorf("generate iv: %w", err)
	}

	// PBKDF2WithHmacSHA256(pin, salt, 10000, 256) — byte identical to Android for numeric PINs.
	key := pbkdf2.Key([]byte(usedPin), salt, shareIterations, shareKeyLen, sha256.New)

	block, cErr := aes.NewCipher(key)
	if cErr != nil {
		return "", usedPin, cErr
	}
	gcm, cErr := cipher.NewGCM(block)
	if cErr != nil {
		return "", usedPin, cErr
	}
	// AES/GCM/NoPadding, GCMParameterSpec(128, iv) → 16-byte tag, appended after ciphertext.
	ciphertext := gcm.Seal(nil, iv, raw, nil)

	env := shareEnvelope{
		V: 1,
		S: base64.StdEncoding.EncodeToString(salt),
		I: base64.StdEncoding.EncodeToString(iv),
		C: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if len(raw) < len(plainText) { // gzip was applied
		env.G = 1
	}

	envBytes, mErr := json.Marshal(env)
	if mErr != nil {
		return "", usedPin, mErr
	}
	uri = "stun://" + base64.StdEncoding.EncodeToString(envBytes)
	return uri, usedPin, nil
}

// decryptStunURI reverses encryptStunURI (parity with ShareCryptoUtils.decrypt). Used for tests
// and any future import tooling. Accepts the URI with or without the "stun://" scheme.
func decryptStunURI(payload, pin string) (string, error) {
	clean := payload
	if len(clean) > 7 && clean[:7] == "stun://" {
		clean = clean[7:]
	}
	// Strip whitespace / BOM the way the Android client does before decoding.
	clean = stripWs(clean)
	if base64.StdEncoding.DecodedLen(len(clean)) > shareMaxSize {
		return "", fmt.Errorf("share envelope is larger than %d bytes", shareMaxSize)
	}

	envBytes, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", err
	}
	var env shareEnvelope
	if err = json.Unmarshal(envBytes, &env); err != nil {
		return "", err
	}
	if env.V != 1 {
		return "", fmt.Errorf("unsupported share envelope version %d", env.V)
	}
	if env.G != 0 && env.G != 1 {
		return "", fmt.Errorf("unsupported share compression flag %d", env.G)
	}
	salt, err := base64.StdEncoding.DecodeString(env.S)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(env.I)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(env.C)
	if err != nil {
		return "", err
	}
	if len(salt) != shareSaltLen {
		return "", fmt.Errorf("invalid share salt length %d", len(salt))
	}
	if len(iv) != shareIvLen {
		return "", fmt.Errorf("invalid share nonce length %d", len(iv))
	}
	if len(ct) < 16 {
		return "", fmt.Errorf("share ciphertext is too short")
	}

	key := pbkdf2.Key([]byte(pin), salt, shareIterations, shareKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", err
	}
	if env.G == 1 {
		if plain, err = gunzipData(plain); err != nil {
			return "", err
		}
	}
	return string(plain), nil
}

func stripWs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\r' || r == '\uFEFF' || r == '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
