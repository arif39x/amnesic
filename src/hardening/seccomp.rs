use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};

pub fn apply_filters() {
    println!("[*] Initializing Seccomp Prison...");

    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Trap)
        .expect("Failed to initialize Seccomp filter");

    const ALLOWED_SYSCALLS: &[i64] = &[
        libc::SYS_read, libc::SYS_write, libc::SYS_writev, libc::SYS_openat, libc::SYS_close, libc::SYS_exit_group, libc::SYS_exit,
        libc::SYS_brk, libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mprotect, libc::SYS_mlockall, libc::SYS_madvise, libc::SYS_rseq,
        libc::SYS_fstat, libc::SYS_newfstatat, libc::SYS_statx, libc::SYS_lseek, libc::SYS_ioctl, libc::SYS_fcntl,
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_set_robust_list, libc::SYS_futex, libc::SYS_set_tid_address, libc::SYS_tgkill, libc::SYS_gettid,
        libc::SYS_nanosleep, libc::SYS_rt_sigreturn, libc::SYS_rt_sigaction, libc::SYS_sigaltstack, libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigsuspend, 
        libc::SYS_getrandom, libc::SYS_prlimit64, libc::SYS_getuid, libc::SYS_getgid, libc::SYS_geteuid, libc::SYS_getegid,
        libc::SYS_ptrace, 
        libc::SYS_poll, libc::SYS_ppoll, libc::SYS_select, libc::SYS_pselect6, libc::SYS_epoll_pwait,
        libc::SYS_getpgrp, libc::SYS_getpid, libc::SYS_getppid, libc::SYS_arch_prctl, libc::SYS_sched_getaffinity,
    ];

    for &syscall_nr in ALLOWED_SYSCALLS {
        let syscall = ScmpSyscall::from(syscall_nr as i32);
        ctx.add_rule(ScmpAction::Allow, syscall)
            .unwrap_or_else(|_| panic!("Failed to allow syscall: {}", syscall_nr));
    }

    ctx.load().expect("Failed to load Seccomp filter into Kernel");

    println!("[*] Seccomp Prison: ACTIVE ");
}
