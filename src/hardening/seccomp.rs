use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

pub fn enforce_syscall_boundaries() {
    println!("[*] Initializing Seccomp Prison...");

    let mut isolation_context = ScmpFilterContext::new_filter(ScmpAction::Trap)
        .expect("Isolation initialization failed");

    const PERMITTED_SYSTEM_CALLS: &[i32] = &[
        libc::SYS_read as i32,
        libc::SYS_write as i32,
        libc::SYS_writev as i32,
        libc::SYS_open as i32,
        libc::SYS_openat as i32,
        libc::SYS_close as i32,
        libc::SYS_exit_group as i32,
        libc::SYS_exit as i32,
        libc::SYS_brk as i32,
        libc::SYS_mmap as i32,
        libc::SYS_munmap as i32,
        libc::SYS_mremap as i32,
        libc::SYS_mprotect as i32,
        libc::SYS_mlockall as i32,
        libc::SYS_munlockall as i32,
        libc::SYS_madvise as i32,
        libc::SYS_rseq as i32,
        libc::SYS_fstat as i32,
        libc::SYS_newfstatat as i32,
        libc::SYS_statx as i32,
        libc::SYS_lseek as i32,
        libc::SYS_ioctl as i32,
        libc::SYS_fcntl as i32,
        libc::SYS_clone as i32,
        libc::SYS_clone3 as i32,
        libc::SYS_set_robust_list as i32,
        libc::SYS_futex as i32,
        libc::SYS_set_tid_address as i32,
        libc::SYS_tgkill as i32,
        libc::SYS_gettid as i32,
        libc::SYS_nanosleep as i32,
        libc::SYS_rt_sigreturn as i32,
        libc::SYS_rt_sigaction as i32,
        libc::SYS_sigaltstack as i32,
        libc::SYS_rt_sigprocmask as i32,
        libc::SYS_rt_sigsuspend as i32,
        libc::SYS_getrandom as i32,
        libc::SYS_prlimit64 as i32,
        libc::SYS_getuid as i32,
        libc::SYS_getgid as i32,
        libc::SYS_geteuid as i32,
        libc::SYS_getegid as i32,
        libc::SYS_ptrace as i32,
        libc::SYS_poll as i32,
        libc::SYS_ppoll as i32,
        libc::SYS_select as i32,
        libc::SYS_pselect6 as i32,
        libc::SYS_epoll_pwait as i32,
        libc::SYS_getpgrp as i32,
        libc::SYS_getpid as i32,
        libc::SYS_getppid as i32,
        libc::SYS_arch_prctl as i32,
        libc::SYS_sched_getaffinity as i32,
    ];

    for &system_call_identifier in PERMITTED_SYSTEM_CALLS {
        let kernel_syscall = ScmpSyscall::from(system_call_identifier);
        isolation_context
            .add_rule(ScmpAction::Allow, kernel_syscall)
            .unwrap_or_else(|_| panic!("Failed to allow syscall ID: {}", system_call_identifier));
    }

    isolation_context.load().expect("Kernel context switch failed");

    println!("[*] Seccomp Prison: ACTIVE ");
}
