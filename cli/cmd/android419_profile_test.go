package cmd

import (
	"testing"

	"github.com/gojue/ecapture/v2/internal/config"
	opensslProbe "github.com/gojue/ecapture/v2/internal/probe/openssl"
)

func TestAndroid419Request(t *testing.T) {
	previousCommon, previousSSL := globalConf, opensslConfig
	t.Cleanup(func() { globalConf, opensslConfig = previousCommon, previousSSL })
	for _, tt := range []struct {
		name    string
		change  func()
		command string
		ok      bool
	}{
		{"targeted-text", func() {}, "tls", true},
		{"all-pids", func() { globalConf.Pid = 0 }, "tls", false},
		{"pid-overflow", func() { globalConf.Pid = 1 << 32 }, "tls", false},
		{"uid-overflow", func() { globalConf.Uid = 1 << 32 }, "tls", false},
		{"core", func() { globalConf.BTFMode = 1 }, "tls", false},
		{"reload", func() { globalConf.Listen = "127.0.0.1:28256" }, "tls", false},
		{"cgroup", func() { globalConf.CGroupPath = "/sys/fs/cgroup" }, "tls", false},
		{"implicit-lib", func() { opensslConfig.OpensslPath = "" }, "tls", false},
		{"relative-lib", func() { opensslConfig.OpensslPath = "libssl.so" }, "tls", false},
		{"pcap", func() { opensslConfig.CaptureMode = "pcap" }, "tls", false},
		{"keylog", func() { opensslConfig.CaptureMode = "keylog" }, "tls", false},
		{"pcap-text", func() { opensslConfig.TextSource = "pcapng" }, "tls", false},
		{"other-module", func() {}, "gotls", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			globalConf = CLIConfig{CommonConfig: config.CommonConfig{Pid: 123, BTFMode: 2}}
			opensslConfig = opensslProbe.NewConfig()
			opensslConfig.OpensslPath = "/data/local/tmp/test/libssl.so"
			tt.change()
			if err := validateAndroid419Request(tt.command); (err == nil) != tt.ok {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
