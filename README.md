# netless-rust

Run a program under the operating system's network restriction mechanism. Network access is denied by default and there is no option to enable it.

```sh
cargo build --release
./target/release/netless -- curl https://example.com
```

The target runs normally; socket creation or network operations are rejected by the platform policy. Linux also accepts extra syscall denials:

```sh
netless --deny-syscall ptrace --deny-syscall mount -- COMMAND ARGUMENTS
```

On Linux, add a separate network namespace for defense in depth:

```sh
netless --network-namespace -- COMMAND ARGUMENTS
```

This mode requires Bubblewrap (`bwrap`) and permission to create a network namespace. It places the target in a new namespace with no host network interfaces or routes, then installs netless's seccomp filter before executing the target. If Bubblewrap is missing or cannot create the namespace, the target is not started. Namespace creation can be restricted by the host or an outer container. Ordinary Linux mode does not require Bubblewrap and still denies network socket syscalls for the full descendant process tree.

## Platform matrix

| Platform | CPU targets | Mechanism | Status |
|---|---|---|---|
| Linux | x86_64, AArch64 | seccomp-BPF; denies socket, io_uring, pidfd_getfd, ptrace; rejects wrong audit architecture and x32 ABI calls; optional Bubblewrap network namespace | Strict direct network-syscall denial when kernel filter support exists; namespace mode adds an independent network-stack boundary; dynamic GNU and static musl assets |
| macOS | Intel x86_64, Apple Silicon arm64 | Seatbelt profile through `/usr/bin/sandbox-exec` | Implemented; CI-tested |
| OpenBSD | x86_64 | `pledge` with no inet/dns/unix promises | Implemented; built/tested in native VM |
| FreeBSD | x86_64 | jail with IPv4/IPv6 disabled and raw sockets denied | Best effort; requires root; AF_LOCAL and host filesystem remain exposed |
| Windows 10/11 | x86_64, ARM64 | AppContainer process with zero network capabilities | Best effort; AppContainer also restricts files, registry, and IPC; does not prevent every socket syscall or loopback |

Unsupported operating systems fail at compile time; the program does not silently run unrestricted.

### Linux kernel and legacy distributions

Linux installs `no_new_privs` and a seccomp filter before the target starts. Failure to install either is fail-closed. The filter is inherited by forks and execs. It blocks socket-related syscalls and `io_uring`; on x86_64 it rejects both tagged x32 calls and syscall numbers 512–547 used by the old x32 compatibility ABI on kernels before Linux 5.4.

Use `netless-rust-linux-*-musl-static.tar.gz` on older glibc distributions. Static musl removes the glibc runtime dependency, but it does not make an unsupported kernel compatible. Seccomp filter mode and `no_new_privs` require Linux 3.5 or later. Therefore stock CentOS 6 (kernel 2.6.32) cannot run the strict Linux backend and fails closed. CentOS 7 x86_64 and CentOS 8 x86_64 meet the kernel floor; verify that seccomp filter support is enabled. Rust's GNU AArch64 target requires Linux 4.1+, so stock CentOS 7 AArch64 is not covered by that GNU release. Musl assets are provided for x86_64 and AArch64, but the kernel seccomp floor still applies.

Container smoke tests establish distribution userspace compatibility only; containers share their host kernel. They do not establish that a stock CentOS 6 kernel supports the filter.

Linux's default seccomp backend is **not best effort for direct networking**: the kernel denies socket and related network syscalls in the launched process and its descendants, including when a shell invokes another program. Bubblewrap network-namespace mode additionally removes the target's host network interfaces and routes, so another network API or socket operation still has no path to the host network. These controls do not stop a separate host service from acting as a proxy if the workload can communicate with it through a non-network channel; filesystem and IPC isolation are separate controls.

### Limitations

The FreeBSD jail uses `/` as its root, leaves local Unix sockets available, and may expose host services that can relay network requests. Windows AppContainer restricts but does not completely deny socket syscalls; tests document the observed best-effort behavior. A more complete Windows policy may use Windows Filtering Platform filters, which need elevated filter-management rights. No backend blocks an independent privileged broker that a workload can ask to make network requests.

The macOS backend relies on Apple's `sandbox-exec` utility, which is deprecated and may change in a future macOS release. OpenBSD pledge is intentionally limited to the existing promise set, which preserves ordinary file and process behavior while omitting network promises.

## Build and test

```sh
cargo test
cargo build --release
```

OpenBSD is built in a native OpenBSD VM with its packaged Rust toolchain because the Rust target is Tier 3 and rustup does not publish a prebuilt standard library for it. CI builds and tests each supported OS/architecture. Network denial tests attempt active socket/network operations; a passing job reports evidence for that runner image and is not a proof for every system configuration.

## License

MIT. See [LICENSE](LICENSE).
