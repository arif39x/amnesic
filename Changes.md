# Architectural Mutation Directive: Zero-Overhead Sandbox Refactor

## 1. Resolve the Tracing Collision (Target: `anti_debug.rs` & `watchdog.rs`)
**The Flaw:** `watchdog.rs` initiates a `ptrace` lock on the child process. `anti_debug.rs` subsequently attempts to acquire the exact same lock, mathematically guaranteeing a failure and triggering a false-positive self-termination.
**The Mutation:** * Navigate to `anti_debug.rs`.
* Strip out the `ptrace(PTRACE_TRACEME)` check entirely. The child process is already being strictly supervised by your custom watchdog parent; redundant kernel-level polling here only causes pipeline halts and fatal collisions.

## 2. Synchronize the Seccomp Prison (Target: `main.rs`)
**The Flaw:** Background threads spawned before Seccomp initialization operate outside the kernel's BPF sandbox, creating a critical escape vector.
**The Mutation:**
* Open `main.rs`.
* Reorder the initialization sequence within your `secure_launch` closure.
* You must invoke your Seccomp module *before* invoking `signals::install_signal_handlers()`. This guarantees the signal-listening thread inherits the strictly defined syscall boundaries.

## 3. Eradicate Mutex Poisoning (Target: `secrets/secret.rs`)
**The Flaw:** Standard `Arc<Mutex>` structures panic-lock during a crash. If a panic unwinds while the lock is held, the emergency memory wipe will fail, leaving cryptographic material in contiguous memory.
**The Mutation:**
* Strip `Arc`, `Mutex`, and `lazy_static` from the module imports.
* Replace the dynamic `Vec<Box<dyn Fn()>>` registry with a static, compile-time sized array of `AtomicPtr`.
* Refactor the wipe logic to iterate over this atomic array using `Swap` operations with `Ordering::SeqCst`. This establishes mathematical determinism: the wipe will execute sequentially without locking overhead, even during a catastrophic unwinding event.

## 4. Enforce Zero-Overhead Allocations (Target: `namespace.rs` & `seccomp.rs`)
**The Flaw:** "Lazy abstractions" utilizing the heap (`Vec`, `String`, `format!`) introduce CPU stalls, vtable lookups, and garbage collection pressure in critical security pathways.
**The Mutation:**
* In `seccomp.rs`, delete the runtime string-to-syscall parsing. Replace it with a hardcoded `const` array of raw integer slices (`&[i32]`) mapping directly to `libc::SYS_*` constants. 
* In `namespace.rs`, eliminate the `format!` macros used to generate UID/GID mappings. Pre-allocate a fixed-size byte buffer (`[0u8; 64]`) on the stack and write the integer mappings directly into the buffer using a cursor, pushing the raw bytes directly to `/proc/self/uid_map`.