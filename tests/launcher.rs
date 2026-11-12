#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::fs::MetadataExt;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netless"))
}

#[test]
fn help_and_argument_errors_are_clear() {
    let help = bin().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("OS-enforced network restrictions"));
    let bad = bin().args(["--", "true"]).output().unwrap();
    assert!(bad.status.success());
    let missing = bin().output().unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn denies_network_syscalls_before_exec_and_in_descendants() {
    let python = r#"import errno, socket, subprocess, sys
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX, getattr(socket, 'AF_PACKET', socket.AF_UNIX)):
    try: socket.socket(family, socket.SOCK_STREAM)
    except OSError as e: assert e.errno == errno.EPERM, (family, e)
    else: raise AssertionError(f'socket family {family} was allowed')
subprocess.run([sys.executable, '-c', "import socket; socket.socket()"], check=False)
child = subprocess.run([sys.executable, '-c', "import socket; socket.socket()"], capture_output=True)
assert child.returncode != 0
"#;
    let result = bin()
        .args(["--", "python3", "-c", python])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn accepts_extra_denial_from_supported_syscall_table() {
    let result = bin()
        .args(["--deny-syscall", "ptrace", "--", "true"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bad = bin()
        .args(["--deny-syscall", "not_a_syscall", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn blocks_legacy_x32_syscall_number_range() {
    let script = "import ctypes, errno; libc=ctypes.CDLL(None, use_errno=True); assert libc.syscall(512) == -1; assert ctypes.get_errno() == errno.EPERM";
    let result = bin()
        .args(["--", "python3", "-c", script])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn blocks_network_access_from_system_shell_descendants() {
    let script = r#"import os, sys
status = os.system("python3 -c 'import socket; socket.socket()'")
assert status != 0, status
"#;
    let result = bin()
        .args(["--", "python3", "-c", script])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn bubblewrap_mode_uses_a_distinct_network_namespace() {
    let host_namespace = std::fs::metadata("/proc/self/ns/net").unwrap().ino();
    let result = bin()
        .args([
            "--network-namespace",
            "--",
            "python3",
            "-c",
            "import os; print(os.stat('/proc/self/ns/net').st_ino)",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let child_namespace: u64 = String::from_utf8_lossy(&result.stdout)
        .trim()
        .parse()
        .unwrap();
    assert_ne!(
        host_namespace, child_namespace,
        "network namespace was shared"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_seatbelt_rejects_socket_creation() {
    let result = bin()
        .args(["--", "python3", "-c", "import socket; socket.socket()"])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "socket creation unexpectedly succeeded"
    );
}

#[cfg(windows)]
#[test]
fn appcontainer_launches_command_and_propagates_exit_status() {
    let result = bin()
        .args(["--", "cmd.exe", "/d", "/c", "exit", "23"])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(windows)]
#[test]
fn appcontainer_network_probe_records_socket_boundary() {
    let result = bin()
        .args(["--", env!("CARGO_BIN_EXE_network_probe")])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = String::from_utf8_lossy(&result.stdout);
    assert!(report.contains("loopback TCP bind"), "{report}");
    assert!(report.contains("loopback UDP"), "{report}");
    eprintln!("AppContainer socket behavior (best-effort backend):\n{report}");
}
