const USAGE: &str = "Usage: netless [--network-namespace] [--deny-syscall NAME]... -- COMMAND [ARG...]\nRun COMMAND with OS-enforced network restrictions.\nOn Linux, --network-namespace adds a bubblewrap network namespace (requires bwrap).\n";

fn parse_args() -> Result<(bool, Vec<String>, Vec<String>), u8> {
    let mut args = std::env::args().skip(1);
    let mut denied = Vec::new();
    let mut network_namespace = false;
    loop {
        match args.next().as_deref() {
            Some("--help") => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            Some("--deny-syscall") => match args.next() {
                Some(name) => denied.push(name),
                None => {
                    eprint!("{USAGE}");
                    return Err(2);
                }
            },
            Some("--network-namespace") => network_namespace = true,
            Some("--") => break,
            _ => {
                eprint!("{USAGE}");
                return Err(2);
            }
        }
    }
    let command: Vec<String> = args.collect();
    if command.is_empty() {
        eprint!("{USAGE}");
        return Err(2);
    }
    Ok((network_namespace, denied, command))
}

#[cfg(target_os = "linux")]
mod backend {
    use libc::{c_ulong, c_ushort};
    use std::{io, os::unix::process::CommandExt, process::Command};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct Program {
        len: c_ushort,
        filter: *const Filter,
    }

    const LD_W_ABS: u16 = 0x20;
    const JMP_JEQ_K: u16 = 0x15;
    #[cfg(target_arch = "x86_64")]
    const JMP_JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_THREAD: u32 = 0;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const PR_SET_SECCOMP: libc::c_int = 22;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    fn syscall_table() -> Vec<(&'static str, libc::c_long)> {
        vec![
            ("socket", libc::SYS_socket),
            ("socketpair", libc::SYS_socketpair),
            ("connect", libc::SYS_connect),
            ("bind", libc::SYS_bind),
            ("listen", libc::SYS_listen),
            ("accept", libc::SYS_accept),
            ("accept4", libc::SYS_accept4),
            ("sendto", libc::SYS_sendto),
            ("recvfrom", libc::SYS_recvfrom),
            ("sendmsg", libc::SYS_sendmsg),
            ("recvmsg", libc::SYS_recvmsg),
            ("shutdown", libc::SYS_shutdown),
            ("getsockname", libc::SYS_getsockname),
            ("getpeername", libc::SYS_getpeername),
            ("setsockopt", libc::SYS_setsockopt),
            ("getsockopt", libc::SYS_getsockopt),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("ptrace", libc::SYS_ptrace),
        ]
    }

    fn audit_arch() -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            0xc000003e
        }
        #[cfg(target_arch = "aarch64")]
        {
            0xc00000b7
        }
    }

    fn make_filter(extra: &[String]) -> Result<Vec<Filter>, String> {
        let table = syscall_table();
        let mut numbers: Vec<u32> = table.iter().map(|(_, n)| *n as u32).collect();
        for name in extra {
            let Some((_, n)) = table.iter().find(|(key, _)| key == name) else {
                return Err(format!("netless: unsupported syscall name: {name}"));
            };
            numbers.push(*n as u32);
        }
        if extra.len() > 32 {
            return Err("netless: too many additional syscall denials".into());
        }
        let mut code = vec![
            Filter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            Filter {
                code: JMP_JEQ_K,
                jt: 1,
                jf: 0,
                k: audit_arch(),
            },
            Filter {
                code: RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_THREAD,
            },
            Filter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        #[cfg(target_arch = "x86_64")]
        {
            // Deny x32 calls. Old kernels also need the historical untagged x32 range blocked.
            code.push(Filter {
                code: JMP_JSET_K,
                jt: 0,
                jf: 1,
                k: 0x40000000,
            });
            code.push(Filter {
                code: RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
            });
            for n in 512..=547 {
                code.push(Filter {
                    code: JMP_JEQ_K,
                    jt: 0,
                    jf: 1,
                    k: n,
                });
                code.push(Filter {
                    code: RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
                });
            }
        }
        for n in numbers {
            code.push(Filter {
                code: JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: n,
            });
            code.push(Filter {
                code: RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
            });
        }
        code.push(Filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
        Ok(code)
    }

    fn prepare_fds() -> io::Result<()> {
        unsafe {
            for fd in 0..3 {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "refusing inherited socket on standard fd",
                    ));
                }
            }
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            let maxfd = if limit.rlim_cur == libc::RLIM_INFINITY {
                1_048_576
            } else {
                limit.rlim_cur.min(1_048_576) as libc::c_int
            };
            for fd in 3..maxfd {
                if libc::close(fd) != 0 && *libc::__errno_location() != libc::EBADF {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    pub fn launch(network_namespace: bool, extra: &[String], args: &[String]) -> Result<u32, u8> {
        let filter = make_filter(extra).map_err(|e| {
            eprintln!("{e}");
            2
        })?;
        if network_namespace {
            let exe = std::env::current_exe().map_err(|e| {
                eprintln!("netless: locating launcher for bubblewrap: {e}");
                125
            })?;
            let mut bwrap = Command::new("bwrap");
            bwrap.args([
                "--unshare-net",
                "--bind",
                "/",
                "/",
                "--die-with-parent",
                "--",
            ]);
            bwrap.arg(exe);
            for name in extra {
                bwrap.args(["--deny-syscall", name]);
            }
            bwrap.arg("--").args(args);
            prepare_fds().map_err(|e| {
                eprintln!("netless: preparing descriptors: {e}");
                125
            })?;
            let err = bwrap.exec();
            eprintln!("netless: starting bubblewrap network namespace: {err}");
            return Err(if err.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
        let mut cmd = Command::new(&args[0]);
        cmd.args(&args[1..]);
        prepare_fds().map_err(|e| {
            eprintln!("netless: preparing descriptors: {e}");
            125
        })?;
        unsafe {
            if libc::prctl(PR_SET_NO_NEW_PRIVS, 1 as c_ulong, 0, 0, 0) != 0 {
                eprintln!(
                    "netless: PR_SET_NO_NEW_PRIVS: {}",
                    io::Error::last_os_error()
                );
                return Err(125);
            }
            let program = Program {
                len: filter.len() as c_ushort,
                filter: filter.as_ptr(),
            };
            if libc::prctl(
                PR_SET_SECCOMP,
                2 as c_ulong,
                &program as *const Program,
                0,
                0,
            ) != 0
            {
                eprintln!(
                    "netless: installing seccomp filter: {}",
                    io::Error::last_os_error()
                );
                return Err(125);
            }
        }
        let err = cmd.exec();
        eprintln!("netless: exec: {err}");
        Err(if err.kind() == io::ErrorKind::NotFound {
            127
        } else {
            126
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "freebsd"))]
mod backend {
    use std::{io, os::unix::process::CommandExt, process::Command};

    fn prepare_fds() -> io::Result<()> {
        unsafe {
            for fd in 0..3 {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("refusing inherited socket on standard fd {fd}"),
                    ));
                }
            }
            #[cfg(target_os = "openbsd")]
            libc::closefrom(3);
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                let mut limit: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let max = if limit.rlim_cur == libc::RLIM_INFINITY {
                    1_048_576
                } else {
                    limit.rlim_cur as i32
                };
                for fd in 3..max {
                    if libc::close(fd) != 0 && *libc::__error() != libc::EBADF {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn launch(network_namespace: bool, _extra: &[String], args: &[String]) -> Result<u32, u8> {
        if network_namespace {
            eprintln!("netless: --network-namespace is only available on Linux");
            return Err(2);
        }
        #[cfg(target_os = "freebsd")]
        {
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("netless: FreeBSD jail backend requires root");
                return Err(125);
            }
            prepare_fds().map_err(|e| {
                eprintln!("netless: {e}");
                125
            })?;
            let jail = format!("name=netless-{}", unsafe { libc::getpid() });
            let mut cmd = Command::new("/usr/sbin/jail");
            cmd.args([
                "-c",
                &jail,
                "path=/",
                "host.hostname=netless",
                "ip4=disable",
                "ip6=disable",
                "allow.raw_sockets=0",
                "allow.socket_af=0",
            ]);
            let command = format!("command={}", args[0]);
            cmd.arg(command).args(&args[1..]);
            let e = cmd.exec();
            eprintln!("netless: exec jail: {e}");
            return Err(if e.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
        #[cfg(target_os = "openbsd")]
        {
            unsafe extern "C" {
                fn pledge(
                    promises: *const libc::c_char,
                    execpromises: *const libc::c_char,
                ) -> libc::c_int;
            }
            prepare_fds().map_err(|e| {
                eprintln!("netless: {e}");
                125
            })?;
            let p =
                std::ffi::CString::new("stdio rpath wpath cpath dpath proc exec prot_exec error")
                    .unwrap();
            if unsafe { pledge(p.as_ptr(), p.as_ptr()) } != 0 {
                eprintln!("netless: pledge: {}", io::Error::last_os_error());
                return Err(125);
            }
            let mut c = Command::new(&args[0]);
            c.args(&args[1..]);
            let e = c.exec();
            eprintln!("netless: exec: {e}");
            return Err(if e.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
        #[cfg(target_os = "macos")]
        {
            prepare_fds().map_err(|e| {
                eprintln!("netless: {e}");
                125
            })?;
            let profile = "(version 1) (deny network*) (deny system-socket) (allow default)";
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", profile, "--", &args[0]]).args(&args[1..]);
            let e = c.exec();
            eprintln!("netless: exec: {e}");
            return Err(if e.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
    }
}

#[cfg(windows)]
mod backend {
    use std::{
        ffi::OsStr,
        mem::{size_of, zeroed},
        os::windows::ffi::OsStrExt,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE,
            WAIT_OBJECT_0,
        },
        Networking::WinSock::{SO_TYPE, SOL_SOCKET, WSACleanup, WSADATA, WSAStartup, getsockopt},
        Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile},
        Security::{FreeSid, SECURITY_CAPABILITIES},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        System::Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            GetCurrentProcess, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
            UpdateProcThreadAttribute, WaitForSingleObject,
        },
    };

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }
    fn quote(arg: &[u16]) -> Vec<u16> {
        let mut out = vec![b'"' as u16];
        let mut slashes = 0usize;
        for &ch in arg {
            if ch == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            if ch == b'"' as u16 {
                out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
                out.push(ch);
            } else {
                out.extend(std::iter::repeat_n(b'\\' as u16, slashes));
                out.push(ch);
            }
            slashes = 0;
        }
        out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        out.push(b'"' as u16);
        out
    }

    pub fn launch(network_namespace: bool, _extra: &[String], args: &[String]) -> Result<u32, u8> {
        if network_namespace {
            eprintln!("netless: --network-namespace is only available on Linux");
            return Err(2);
        }
        unsafe {
            let nonce = format!("netless-{}-{}", GetCurrentProcessId(), GetTickCount());
            let name = wide(OsStr::new(&nonce));
            let display = wide(OsStr::new("netless"));
            let desc = wide(OsStr::new("network-restricted command"));
            let mut sid = ptr::null_mut();
            let hr = CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                desc.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            );
            if hr < 0 || sid.is_null() {
                eprintln!(
                    "netless: CreateAppContainerProfile failed: 0x{:08x}",
                    hr as u32
                );
                return Err(125);
            }
            let mut caps = SECURITY_CAPABILITIES {
                AppContainerSid: sid,
                Capabilities: ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            let mut startup: STARTUPINFOEXW = zeroed();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            let mut wsa: WSADATA = zeroed();
            if WSAStartup(0x0202, &mut wsa) != 0 {
                let _ = DeleteAppContainerProfile(name.as_ptr());
                let _ = FreeSid(sid);
                eprintln!("netless: WSAStartup failed");
                return Err(125);
            }
            let current = GetCurrentProcess();
            let std_ids = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
            let mut dup: [HANDLE; 3] = [ptr::null_mut(); 3];
            let mut handles_ok = true;
            for i in 0..3 {
                let original = GetStdHandle(std_ids[i]);
                if original.is_null() || original as isize == -1 {
                    continue;
                }
                let mut typ = 0i32;
                let mut len = size_of::<i32>() as i32;
                if getsockopt(
                    original as usize,
                    SOL_SOCKET,
                    SO_TYPE,
                    (&mut typ as *mut i32).cast(),
                    &mut len,
                ) == 0
                {
                    eprintln!("netless: refusing inherited socket on standard handle {i}");
                    handles_ok = false;
                    break;
                }
                if DuplicateHandle(
                    current,
                    original,
                    current,
                    &mut dup[i],
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                ) == 0
                {
                    handles_ok = false;
                    break;
                }
            }
            startup.StartupInfo.hStdInput = dup[0];
            startup.StartupInfo.hStdOutput = dup[1];
            startup.StartupInfo.hStdError = dup[2];
            let mut bytes = 0usize;
            let _ = InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut bytes);
            let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
            let attrs = storage.as_mut_ptr().cast();
            if !handles_ok
                || bytes == 0
                || InitializeProcThreadAttributeList(attrs, 2, 0, &mut bytes) == 0
            {
                eprintln!(
                    "netless: preparing AppContainer process failed: {}",
                    GetLastError()
                );
                for h in dup {
                    if !h.is_null() {
                        let _ = CloseHandle(h);
                    }
                }
                let _ = WSACleanup();
                let _ = DeleteAppContainerProfile(name.as_ptr());
                let _ = FreeSid(sid);
                return Err(125);
            }
            startup.lpAttributeList = attrs;
            let inherited: Vec<HANDLE> = dup.iter().copied().filter(|h| !h.is_null()).collect();
            let mut ok = UpdateProcThreadAttribute(
                attrs,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&mut caps as *mut SECURITY_CAPABILITIES).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            ) != 0;
            if ok && !inherited.is_empty() {
                ok = UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    inherited.as_ptr().cast(),
                    inherited.len() * size_of::<HANDLE>(),
                    ptr::null_mut(),
                    ptr::null(),
                ) != 0;
            }
            let mut cmdline: Vec<u16> = Vec::new();
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    cmdline.push(b' ' as u16);
                }
                let w = wide(OsStr::new(arg));
                cmdline.extend(quote(&w[..w.len() - 1]));
            }
            cmdline.push(0);
            let mut pi: PROCESS_INFORMATION = zeroed();
            let created = ok
                && CreateProcessW(
                    ptr::null(),
                    cmdline.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    (!inherited.is_empty()) as i32,
                    EXTENDED_STARTUPINFO_PRESENT,
                    ptr::null(),
                    ptr::null(),
                    &startup.StartupInfo as *const STARTUPINFOW,
                    &mut pi,
                ) != 0;
            let create_error = GetLastError();
            for h in dup {
                if !h.is_null() {
                    let _ = CloseHandle(h);
                }
            }
            DeleteProcThreadAttributeList(attrs);
            let _ = storage;
            let _ = WSACleanup();
            let _ = FreeSid(sid);
            if !created {
                let _ = DeleteAppContainerProfile(name.as_ptr());
                eprintln!("netless: CreateProcessW failed: {create_error}");
                return Err(125);
            }
            let _ = CloseHandle(pi.hThread);
            if WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0 {
                let _ = CloseHandle(pi.hProcess);
                let _ = DeleteAppContainerProfile(name.as_ptr());
                return Err(125);
            }
            let mut status = 125u32;
            let _ = GetExitCodeProcess(pi.hProcess, &mut status);
            let _ = CloseHandle(pi.hProcess);
            let _ = DeleteAppContainerProfile(name.as_ptr());
            Ok(status)
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn GetTickCount() -> u32;
    }
}

fn main() {
    let (network_namespace, denied, command) = match parse_args() {
        Ok(v) => v,
        Err(code) => std::process::exit(code as i32),
    };
    match backend::launch(network_namespace, &denied, &command) {
        Ok(code) => std::process::exit(code as i32),
        Err(code) => std::process::exit(code as i32),
    }
}
