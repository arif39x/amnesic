# Amnesic: Transparent Secure Command Wrapper

Amnesic is a high-assurance, identity-isolated command wrapper designed to protect sensitive process execution. It transforms a target binary into a secure "Worker" supervised by an "Amnesic Supervisor" that enforces strict security invariants in physical RAM.

## Core Security Invariants

### 1. Observer Invariant (Ptrace Cloaking)

Amnesic operates on a **Supervisor-Worker** model. Upon execution, the process forks. The Parent (Supervisor) immediately attaches to the Child (Worker) as a tracer. This occupies the sole Linux tracer slot, preventing external debuggers (`gdb`, `strace`) from attaching to the sensitive session.

### 2. Physical Boundary Invariant (mlockall)

Amnesic invokes `mlockall(MCL_CURRENT | MCL_FUTURE)` before yielding control to the target command. This pins all session memory to physical RAM, preventing the OS from swapping sensitive data to persistent disk storage.

### 3. Attack Surface Reduction (Seccomp Jail)

The Worker process is confined within a "Functional-Minimum" Seccomp whitelist. It permits only the necessary syscalls for networking (e.g., `socket`, `connect`, `sendmsg`) and process execution (`execve`), trapping all unauthorized kernel interactions.

### 4. Zero-Persistence Registry

All sensitive buffers are tracked in a global registry. Upon worker termination (or any interruption signal), the Supervisor performs a volatile memory wipe, physically overwriting secret data before the process dissolves.

---

## Installation & Usage

### Build

```bash
cargo build --release
```

### Direct Execution

Wrap any command to run it inside the Amnesic sandbox:

```bash
./target/release/amnesic ls -la
./target/release/amnesic curl -I https://google.com
```

### Interactive Dashboard

Run without arguments to launch the secure CLI dashboard:

```bash
    ./target/release/amnesic
```

---

## Project Structure

- **`src/cli/`**: Interactive dashboard and terminal UI.
- **`src/core/`**: Critical lifecycle management and secret registry.
  - `shutdown.rs`: Destructive cleanup and entropy collapse.
  - `secrets/`: Volatile buffer management.
- **`src/sandbox/`**: Linux-specific hardening primitives.
  - `seccomp.rs`: Syscall filtering and networking whitelist.
  - `namespace.rs`: Filesystem and identity isolation.
  - `watchdog.rs`: Supervisor process and ptrace cloaking.
  - `memory.rs`: Physical RAM locking.

---

## Invariant Summary

- **Inflow:** Strictly whitelisted syscalls.
- **Outflow:** Zero disk persistence; No core dumps.
- **Observation:** Blocked by tracer occupancy.
- **Termination:** Destructive wipe by design.
