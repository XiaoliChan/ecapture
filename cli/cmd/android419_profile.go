// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"fmt"
	"math"
	"path/filepath"

	"github.com/gojue/ecapture/v2/internal/config"
)

// Keep the initial experimental profile narrow. In particular, disabling HTTP
// reload prevents changing the tested PID/library/profile after admission.
func validateAndroid419Request(command string) error {
	if command != "tls" || globalConf.BTFMode != config.BTFModeNonCore ||
		globalConf.Pid == 0 || globalConf.Pid > math.MaxInt32 || globalConf.Uid > math.MaxUint32 ||
		globalConf.Listen != "" || globalConf.CGroupPath != "" ||
		!filepath.IsAbs(opensslConfig.OpensslPath) ||
		opensslConfig.CaptureMode != "text" || opensslConfig.TextSource != "hook" {
		return fmt.Errorf("experimental Android profile requires tls -m text --text-source=hook --btf=2 --pid=<positive PID> --libssl=<absolute path>, valid uint32 UID, and no --listen/--cgroup_path")
	}
	return nil
}
