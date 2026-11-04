# burmalda — Ferrix POSIX Server

`burmalda` is the userspace POSIX personality for the Ferrix microkernel.

It runs as a normal seL4 thread and handles every `seL4_Fault_UnknownSyscall`
fault raised by threads that have `seL4_TCBFlag_posixSyscalls` set (K2 kernel
feature).

---

## Architecture

```
  POSIX thread                   burmalda                kernel
  ─────────────                  ────────────────        ──────────────
  syscall(write, …)
    │  ← TCBFlag_posixSyscalls set
    │                            seL4_Recv(ep)  ←─────── Fault_UnknownSyscall
    │                            burmalda_dispatch(nr=1)
    │                              burmalda_handle_write()
    │                                seL4_DebugPutChar(…)
    │                            seL4_Reply/ReplyRecv
    │  ← rax = bytes_written, rip = FaultIP+2
  returns bytes_written
```

The kernel donates the faulting thread's scheduling context to burmalda on
the fault IPC (MCS builds).  burmalda resumes the thread by **replying with
the full 18-register set** (MRs 0–17), which the kernel copies back via
`copyMRsFaultReply(MessageID_Syscall, 18)`.  This is the only correct
resumption path in MCS — `restart()` would see `tcbSchedContext == NULL`.

---

## Current state (K2 skeleton)

| Syscall | NR | Status |
|---------|----|--------|
| `write` | 1  | ✅ fd 1/2 → `seL4_DebugPutChar` |
| `read`  | 0  | 🔲 returns `ENOSYS` |
| `open`  | 2  | 🔲 returns `ENOSYS` |
| `close` | 3  | 🔲 returns `ENOSYS` |
| `getpid`| 39 | ✅ returns PID 1 (placeholder) |
| `exit`  | 60 | ✅ suspends thread (no reply) |
| `exit_group` | 231 | ✅ same as exit |
| everything else | — | returns `ENOSYS` |

---

## API

`burmalda` is built as a **static library**.  The caller creates the fault
endpoint, sets `seL4_TCBFlag_posixSyscalls` on target threads, and calls:

```c
#include <burmalda/protocol.h>

// non-MCS:  reply_obj is ignored
void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj);

// MCS: reply_obj must be a retyped seL4_ReplyObject
void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj);
```

`burmalda_run` never returns.

---

## Linking into ferrix-init

```cmake
add_subdirectory(../burmalda burmalda)
target_link_libraries(ferrix_init burmalda sel4runtime muslc)
```

---

## Roadmap

| Milestone | Feature |
|-----------|---------|
| K2 (now)  | Dispatch loop skeleton, write/exit |
| M2        | Virtual FD table, real serial driver |
| M3        | `mmap`/`brk` via seL4 Untyped; ELF loader |
| M4        | rump kernel for FS/net syscalls |
| M5        | Signal delivery (rewrite regs before reply) |
| M6        | Multi-process table, `fork`/`exec` |
