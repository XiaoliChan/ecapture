// SPDX-License-Identifier: Apache-2.0
// This diagnostic loads and immediately closes BPF programs; it never attaches.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gojue/ecapture/v2/pkg/util/kernel"
)

func main() {
	v, err := kernel.HostVersion()
	if err != nil || runtime.GOOS != "linux" || runtime.GOARCH != "arm64" ||
		v < kernel.VersionCode(4, 19, 0) || v >= kernel.VersionCode(5, 5, 0) {
		fmt.Fprintf(os.Stderr, "expected experimental Linux/Android arm64 4.19..5.4; got %s/%s %v (%v)\n", runtime.GOOS, runtime.GOARCH, v, err)
		os.Exit(2)
	}
	if _, err := os.Stat("/system/bin/getprop"); err != nil {
		fmt.Fprintln(os.Stderr, "Android system marker missing:", err)
		os.Exit(2)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "process memlock:", err)
		os.Exit(1)
	}
	failed := false
	for _, r := range kernel.ProbeBackportedBPF() {
		if r.Err != nil {
			fmt.Printf("FAIL %s: %+v\n", r.Name, r.Err)
			failed = true
		} else {
			fmt.Println("PASS", r.Name)
		}
	}
	if failed {
		os.Exit(1)
	}
}
