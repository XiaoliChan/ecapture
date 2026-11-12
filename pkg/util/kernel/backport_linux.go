// SPDX-License-Identifier: Apache-2.0

package kernel

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Backported globals are enabled only after the explicit experimental CLI
// profile has passed its load-only preflight. They are not a uname override.
var backportedGlobals atomic.Bool

func BackportedGlobalsEnabled() bool { return backportedGlobals.Load() }

// BPFCheckResult is a preflight result, not a claim of complete TLS compatibility.
type BPFCheckResult struct {
	Name string
	Err  error
}

// ProbeBackportedBPF creates temporary, unpinned maps and loads programs. It
// never attaches a probe, opens a packet socket, or reads application memory.
// All resources are closed before return. Permission errors remain failures.
func ProbeBackportedBPF() []BPFCheckResult {
	checks := []struct {
		name string
		run  func() error
	}{
		{"kprobe-program", func() error { return features.HaveProgramType(ebpf.Kprobe) }},
		{"hash-map", func() error { return features.HaveMapType(ebpf.Hash) }},
		{"percpu-array", func() error { return features.HaveMapType(ebpf.PerCPUArray) }},
		{"perf-event-array", func() error { return features.HaveMapType(ebpf.PerfEventArray) }},
		{"jmp32", features.HaveV3ISA},
		{"large-program", features.HaveLargeInstructions},
		{"frozen-global-data", probeFrozenGlobalData},
	}
	for _, helper := range []asm.BuiltinFunc{
		asm.FnProbeReadUser, asm.FnProbeReadUserStr,
		asm.FnProbeReadKernel, asm.FnProbeReadKernelStr,
		asm.FnGetCurrentPidTgid, asm.FnGetCurrentUidGid,
		asm.FnGetCurrentComm, asm.FnGetCurrentTask,
		asm.FnGetCurrentCgroupId, asm.FnKtimeGetNs,
		asm.FnPerfEventOutput,
	} {
		checks = append(checks, struct {
			name string
			run  func() error
		}{helper.String(), func() error { return features.HaveProgramHelper(ebpf.Kprobe, helper) }})
	}
	results := make([]BPFCheckResult, 0, len(checks))
	for _, check := range checks {
		results = append(results, BPFCheckResult{check.name, check.run()})
	}
	return results
}

// EnableBackportedGlobals fails closed, including inconclusive/permission
// failures. It must only be called by the explicit platform/profile gate.
func EnableBackportedGlobals() error {
	if err := checkResults(ProbeBackportedBPF()); err != nil {
		return err
	}
	backportedGlobals.Store(true)
	return nil
}

func checkResults(results []BPFCheckResult) error {
	if len(results) == 0 {
		return errors.New("empty BPF capability report")
	}
	var errs []error
	for _, result := range results {
		if result.Err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", result.Name, result.Err))
		}
	}
	return errors.Join(errs...)
}

// Exercise the actual .rodata primitives instead of interpreting version >=5.2
// as evidence: readonly-to-BPF array, user initialization, freeze, and direct
// map-value relocation in a tracing program. No program is attached/executed.
func probeFrozenGlobalData() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
		Flags: unix.BPF_F_RDONLY_PROG,
	})
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Update(uint32(0), uint64(0x419), ebpf.UpdateAny); err != nil {
		return err
	}
	if err := m.Freeze(); err != nil {
		return err
	}
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe, License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMapValue(asm.R1, m.FD(), 0),
			asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord),
			asm.Return(),
		},
	})
	if err != nil {
		return err
	}
	return p.Close()
}
