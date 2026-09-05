package tunnel

import (
	"testing"
)

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
