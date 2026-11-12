package cmd

import (
	"errors"
	"syscall"
	"testing"

	"github.com/gojue/ecapture/v2/pkg/util/kernel"
)

func TestMinimumKernelVersion(t *testing.T) {
	tests := []struct {
		goarch string
		want   kernel.Version
		name   string
	}{
		{goarch: "amd64", want: kernel.VersionCode(4, 18, 0), name: "x86_64"},
		{goarch: "arm64", want: kernel.VersionCode(5, 5, 0), name: "aarch64"},
		{goarch: "loong64", want: kernel.VersionCode(6, 6, 0), name: "loongarch64"},
	}
	for _, tt := range tests {
		t.Run(tt.goarch, func(t *testing.T) {
			got, name, err := minimumKernelVersion(tt.goarch)
			if err != nil {
				t.Fatalf("minimumKernelVersion(%q): %v", tt.goarch, err)
			}
			if got != tt.want || name != tt.name {
				t.Fatalf("minimumKernelVersion(%q) = (%v, %q), want (%v, %q)", tt.goarch, got, name, tt.want, tt.name)
			}
		})
	}
	if _, _, err := minimumKernelVersion("mips64"); err == nil {
		t.Fatal("unsupported architecture did not return an error")
	}
}

func TestExperimentalKernelProfile(t *testing.T) {
	for _, tt := range []struct {
		name, arch                               string
		v                                        kernel.Version
		experimental, android, wantProbe, wantOK bool
	}{
		{"default-rejects-419", "arm64", kernel.VersionCode(4, 19, 255), false, true, false, false},
		{"default-accepts-55", "arm64", kernel.VersionCode(5, 5, 0), false, true, false, true},
		{"opt-in-419", "arm64", kernel.VersionCode(4, 19, 255), true, true, true, true},
		{"too-old", "arm64", kernel.VersionCode(4, 18, 0), true, true, false, false},
		{"not-android", "arm64", kernel.VersionCode(4, 19, 0), true, false, false, false},
		{"wrong-arch", "amd64", kernel.VersionCode(4, 19, 0), true, true, false, false},
		{"unnecessary-profile", "arm64", kernel.VersionCode(5, 5, 0), true, true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			err := detectKernelProfile(tt.arch, tt.v, tt.experimental, tt.android, func() error { called = true; return nil })
			if (err == nil) != tt.wantOK || called != tt.wantProbe {
				t.Fatalf("err=%v probe=%v", err, called)
			}
		})
	}
	err := detectKernelProfile("arm64", kernel.VersionCode(4, 19, 0), true, true, func() error { return syscall.EPERM })
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("preflight failure not preserved: %v", err)
	}
}
