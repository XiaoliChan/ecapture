package openssl

import (
	"testing"

	manager "github.com/gojue/ebpfmanager"
)

func TestAndroid419TextProbes(t *testing.T) {
	probes := []*manager.Probe{
		{Section: "uprobe/SSL_read", EbpfFuncName: "probe_entry_SSL_read", AttachPID: 123},
		{Section: "kprobe/sys_connect", EbpfFuncName: "probe_connect"},
		{Section: "uretprobe/SSL_read", EbpfFuncName: "probe_ret_SSL_read"},
		{Section: "uprobe/SSL_write", EbpfFuncName: "probe_entry_SSL_write"},
		{Section: "uretprobe/SSL_write", EbpfFuncName: "probe_ret_SSL_write"},
		{Section: "kretprobe/sys_connect", EbpfFuncName: "retprobe_connect"},
		{Section: "uprobe/SSL_set_fd", EbpfFuncName: "probe_SSL_set_fd"},
	}
	got := android419TextProbes(probes)
	if len(got) != 4 {
		t.Fatalf("unexpected filtered TLS data probe count: %d", len(got))
	}
	for _, probe := range got {
		if probe.AttachPID != 0 {
			t.Fatal("thread-local perf attachment would miss existing app workers")
		}
	}
}
