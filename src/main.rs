mod cli;
mod core;
mod sandbox;

use crate::cli::{interactive_menu, DashboardResult};
use crate::core::secrets::secret::SecureSecret;
use crate::core::shutdown;
use crate::sandbox::{anti_debug, dump, memory, namespace, seccomp, signals, watchdog};
use std::os::unix::process::CommandExt;
use std::panic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let target_args = if args.is_empty() {
        match interactive_menu()? {
            DashboardResult::Execute(cmd_args) => cmd_args,
            DashboardResult::Exit => return Ok(()),
        }
    } else {
        args
    };

    panic::set_hook(Box::new(|info| {
        eprintln!(
            "\n[CRITICAL] Panic detected! {:?}\nExecuting emergency wipe.",
            info
        );
        shutdown::secure_shutdown(1);
    }));

    anti_debug::block_debugger();
    dump::disable_core_dumps();

    watchdog::secure_launch(|| {
        namespace::isolate_environment();
        memory::lock_memory().map_err(|e| format!("{:?}", e))?;
        seccomp::enforce_syscall_boundaries();
        signals::install_signal_handlers();

        let _session_key = SecureSecret::new([0x39u8; 32]);

        let mut cmd = std::process::Command::new(&target_args[0]);
        if target_args.len() > 1 {
            cmd.args(&target_args[1..]);
        }

        let err = cmd.exec();
        Err(Box::new(err))
    });

    Ok(())
}
