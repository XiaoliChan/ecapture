package kernel

import (
	"errors"
	"syscall"
	"testing"
)

func TestBackportChecksFailClosed(t *testing.T) {
	if checkResults(nil) == nil {
		t.Fatal("empty report accepted")
	}
	if err := checkResults([]BPFCheckResult{{Name: "ok"}}); err != nil {
		t.Fatal(err)
	}
	err := checkResults([]BPFCheckResult{{Name: "ok"}, {Name: "denied", Err: syscall.EPERM}})
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("permission failure was lost: %v", err)
	}
	if BackportedGlobalsEnabled() {
		t.Fatal("preflight/report check must not silently enable globals")
	}
}
