# Experimental Android ARM64 backport profile

Base: eCapture v2.10.0 (`eb363adcaeb094eb82c943f60297a2629d14420f`).
This branch adapts the user-space tool, not the phone kernel. Stock upstream
platform minimums remain the default. No uname spoofing is used.

## Scope

`--experimental-android419` is accepted only by an Android ARM64 build on
kernels 4.19 through 5.4, and only for:

- `tls -m text --text-source=hook --btf=2`;
- an explicit positive `--pid` and absolute `--libssl` path;
- optional uint32 `--uid` (zero means no UID filter);
- no HTTP config reload (`--listen`) or cgroup filtering.

The profile loads temporary, unpinned BPF maps/programs to check helper
availability, tracing program type, required map types, JMP32, large programs,
and frozen readonly global-data map access. Nothing is attached during this
preflight. Permission failures and inconclusive checks fail closed. A passed
preflight is not proof that a particular library ABI or probe will work.

Successful preflight enables global constant editing even when uname says
4.19. Both the loader decision and the TLS `less52` constant must agree;
otherwise PID/UID filters can silently become ineffective.

Only the four SSL_read/SSL_write entry/return probes are attached in this
profile. These check TGID/UID before reading application memory. Do not set
perf-event AttachPID to the process leader: that misses existing network
worker threads. Attachment is library-wide, but the BPF filters reject other
processes before payload reads. Connection kprobes and the unfiltered
SSL_set_fd probes are omitted. Connection metadata may therefore be absent.

## Reproduce the tested diagnostic build

Build on Linux, with Go 1.26+, Clang/LLVM 18, GNU Make and ADB. Normal build-host
platform checks still apply. Use exported headers from the exact running
target kernel; arbitrary desktop headers are not interchangeable.

```sh
export ANDROID_SERIAL=YOUR_DEVICE_SERIAL
inputs="$PWD/.build/android419-inputs"
mkdir -p "$inputs/headers"
adb pull /sys/kernel/kheaders.tar.xz "$inputs/kheaders.tar.xz"
tar -xf "$inputs/kheaders.tar.xz" -C "$inputs/headers"
sha256sum "$inputs/kheaders.tar.xz"

go test -race ./cli/cmd ./internal/config ./internal/probe/openssl ./pkg/util/kernel
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -o "$inputs/android419check" ./utils/android419check

make ANDROID=1 TARGET_ARCH=arm64 clean
# Exported kheaders already contain generated headers, not a full Kbuild tree.
make ANDROID=1 TARGET_ARCH=arm64 \
  KERN_HEADERS="$inputs/headers" KERNEL_HEADER_GEN=true \
  TARGETS=kern/boringssl_a_17 CMD_CLANG=clang-18 CMD_LLC=llc-18 assets_noncore

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -tags 'ecap_android,netgo,ebpfassets' \
  -ldflags '-s -w -X github.com/gojue/ecapture/v2/cli/cmd.GitVersion=android419-experimental-v2.10.0-text-threadfix -X github.com/gojue/ecapture/v2/internal/config.ByteCodeFiles=noncore' \
  -o "$inputs/ecapture" ./
```

This is a **pure-Go diagnostic artifact with only the Android 17 BoringSSL
non-CO-RE asset**. It deliberately does not enable the production `dynamic`
libpcap integration, static-PIE release recipe, or other library assets.
Do not publish it as a full-featured release. Other Android/library versions
need their own matching assets and runtime verification.

Run as root, using the library path actually mapped by the target process:

```sh
./ecapture tls --experimental-android419 --btf=2 \
  --pid=12345 --uid=10123 \
  --libssl=/apex/com.android.conscrypt/lib64/libssl.so \
  --ssl_version=boringssl_a_17 -m text --text-source=hook \
  --mapsize=64 --eventaddr=/data/local/tmp/tls-events.txt
```

Use a private output directory, stop with SIGINT, and verify the PID again
after an app restart. Do not commit event files, TLS secrets or application
headers. This profile does not provide an automatic target-lifetime watcher.

## Verification and remaining limitations

Verified on one OnePlus 9R running Android 17 / LineageOS 24, kernel
`4.19.325-cip136-st20-perf-g078365e5318d`, with SELinux Enforcing:

- 18 load-only capability checks passed; no kernel/BTF/SELinux changes.
- Android 17 CO-RE and exact-header non-CO-RE bytecode compilation passed.
  Only non-CO-RE was executed on the phone (kernel BTF is unavailable).
- Targeted Go race tests passed, including platform/profile rejection tests.
- Independent curl requests to a local TLS server produced request/response
  plaintext; a second PID was excluded and a mismatched UID produced no events.
- A user-selected app produced TLS events from six worker threads, all with
  the selected TGID. Shutdown was graceful. No app data is included here.

The full default-tag race run was not green: MySQL tests require an unavailable
`/usr/sbin/mysqld`, and the upgrade API test timed out. Production-tag lint and
the full maintained E2E matrix have not been completed. PCAP/keylog/GoTLS,
other kernel builds, other library ABIs and long-duration capture are not
validated by these results.
