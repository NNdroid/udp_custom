package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// capturePortRangeLog runs validatePortRange with the standard logger diverted
// into a buffer so the emitted warnings can be asserted on.
func capturePortRangeLog(portRange, listen string, origDst bool, sendSockMax int) string {
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	validatePortRange(portRange, listen, origDst, sendSockMax)
	return buf.String()
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name        string
		portRange   string
		listen      string
		origDst     bool
		sendSockMax int
		wantSubstr  []string // every one of these must appear
		denySubstr  []string // none of these may appear
	}{
		{
			name:       "empty is silent",
			listen:     ":36712",
			origDst:    true,
			denySubstr: []string{"⚠️"},
		},
		{
			name:       "healthy range warns about nothing",
			portRange:  "25000-25499",
			listen:     ":36712",
			origDst:    true,
			wantSubstr: []string{"server expects client packets on port range", "25000-25499", "500 ports"},
			denySubstr: []string{"⚠️"},
		},
		{
			name:        "port count above sendsock_max warns",
			portRange:   "25000-25999",
			listen:      ":36712",
			origDst:     true,
			sendSockMax: 512,
			wantSubstr:  []string{"exceeds sendsock_max=512", "1000 ports"},
		},
		{
			name:       "default sendsock_max is used when unset",
			portRange:  "25000-25999",
			listen:     ":36712",
			origDst:    true,
			wantSubstr: []string{"sendsock_max=512"},
		},
		{
			name:       "range with origdst disabled warns",
			portRange:  "25000-25499",
			listen:     ":36712",
			origDst:    false,
			wantSubstr: []string{"origdst=false", "strict NATs drop those"},
		},
		{
			name:       "listen port inside the range warns",
			portRange:  "25000-26000,36712",
			listen:     ":36712",
			origDst:    true,
			wantSubstr: []string{"CONTAINS the listen port 36712", "skip the firewall DNAT"},
		},
		{
			name:       "listen port outside the range does not warn",
			portRange:  "25000-26000",
			listen:     ":36712",
			origDst:    true,
			denySubstr: []string{"CONTAINS the listen port"},
		},
		{
			name:       "host:port listen form is still parsed",
			portRange:  "25000-26000",
			listen:     "127.0.0.1:25500",
			origDst:    true,
			wantSubstr: []string{"CONTAINS the listen port 25500"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := capturePortRangeLog(tc.portRange, tc.listen, tc.origDst, tc.sendSockMax)
			for _, want := range tc.wantSubstr {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in log output:\n%s", want, got)
				}
			}
			for _, deny := range tc.denySubstr {
				if strings.Contains(got, deny) {
					t.Errorf("unexpected %q in log output:\n%s", deny, got)
				}
			}
		})
	}
}

func TestPortRangeContains(t *testing.T) {
	ports, err := ParsePortRangeSpec("1024-1025,23000,25000-25002,36712")
	if err != nil {
		t.Fatalf("ParsePortRangeSpec: %v", err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}

	in := []int{1024, 1025, 23000, 25000, 25001, 25002, 36712}
	for _, p := range in {
		if !pr.Contains(p) {
			t.Errorf("Contains(%d) = false, want true (range %s)", p, pr)
		}
	}
	out := []int{0, 1, 1023, 1026, 22999, 23001, 24999, 25003, 36711, 36713, 65535}
	for _, p := range out {
		if pr.Contains(p) {
			t.Errorf("Contains(%d) = true, want false (range %s)", p, pr)
		}
	}

	// Contains must agree with PortAt over the whole flattened range.
	for i := 0; i < pr.Total(); i++ {
		if p := pr.PortAt(i); !pr.Contains(p) {
			t.Fatalf("PortAt(%d)=%d not reported by Contains", i, p)
		}
	}
}
