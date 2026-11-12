// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/v2/pkg/util/kernel"
)

var experimentalAndroid419 bool

func detectKernel() error {
	// 系统内核版本检测
	kv, err := kernel.HostVersion()
	if err != nil {
		return fmt.Errorf("failed to get the host kernel version: %w", err)
	}
	return detectKernelProfile(runtime.GOARCH, kv, experimentalAndroid419, android419Build, func() error {
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("process memlock: %w", err)
		}
		return kernel.EnableBackportedGlobals()
	})
}

func detectKernelProfile(arch string, kv kernel.Version, experimental, androidBuild bool, probe func() error) error {
	minimum, displayArch, err := minimumKernelVersion(arch)
	if err != nil {
		return err
	}
	if experimental {
		if !androidBuild || arch != "arm64" || kv < kernel.VersionCode(4, 19, 0) || kv >= minimum {
			return fmt.Errorf("experimental Android backport profile requires an Android arm64 build and kernel 4.19..5.4")
		}
		if err := probe(); err != nil {
			return fmt.Errorf("experimental Android BPF preflight failed: %w", err)
		}
		return nil
	}
	if kv < minimum {
		return fmt.Errorf("the Linux/Android kernel version %v (%s) is not supported; require %v or newer", kv, displayArch, minimum)
	}

	return nil
}

func minimumKernelVersion(goarch string) (kernel.Version, string, error) {
	switch goarch {
	case "amd64":
		return kernel.VersionCode(4, 18, 0), "x86_64", nil
	case "arm64":
		return kernel.VersionCode(5, 5, 0), "aarch64", nil
	case "loong64":
		return kernel.VersionCode(6, 6, 0), "loongarch64", nil
	default:
		return 0, "", fmt.Errorf("unsupported CPU arch: %s", goarch)
	}
}
func detectBpfCap() error {
	// BPF 权限检测
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData // why 2? pls check https://github.com/golang/go/issues/44312
	err := unix.Capget(&hdr, &data[0])
	if err != nil {
		return fmt.Errorf("failed to get the capabilities of the current process: %w", err)
	}

	capBpfMask := uint32(1 << (unix.CAP_BPF - 32))
	capSysAdminMask := uint32(1 << unix.CAP_SYS_ADMIN)
	haveBpfCap := (data[1].Permitted&capBpfMask != 0) || (data[0].Permitted&capSysAdminMask != 0)
	if !haveBpfCap {
		return fmt.Errorf("the current user does not have CAP_BPF to load bpf programs. Please run as root or use sudo or add the --privileged=true flag for Docker")
	}

	return nil
}

func detectEnv() error {
	// 环境检测

	if err := detectBpfCap(); err != nil {
		return err
	}

	if err := detectKernel(); err != nil {
		return err
	}

	return nil
}
