/*
 * burmalda/protocol.h — Ferrix POSIX Server IPC protocol constants.
 *
 * burmalda receives seL4_Fault_UnknownSyscall faults from threads that have
 * seL4_TCBFlag_posixSyscalls set.  The fault message carries the full
 * register state of the faulting thread; burmalda inspects the syscall number
 * (MR seL4_UnknownSyscall_Syscall) and the argument registers, then
 * replies with a 18-MR register set that the kernel copies back into the
 * thread (see seL4 manual § "Unknown Syscall" fault).
 *
 * This header defines the Linux x86_64 syscall numbers that burmalda handles
 * and the layout of the fault message on that architecture.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <sel4/sel4_arch/constants.h>  /* seL4_UnknownSyscall_* */

/* -----------------------------------------------------------------------
 * Linux x86_64 syscall numbers (subset implemented in this skeleton).
 * Source: arch/x86/entry/syscalls/syscall_64.tbl in the Linux kernel.
 * ----------------------------------------------------------------------- */
/* Linux errno values (negated on return: return -ENOSYS etc.) */
#define BURMALDA_EBUSY  -16
#define BURMALDA_EXDEV  -18
#define BURMALDA_EISDIR  -21
#define BURMALDA_ENFILE  -23
#define BURMALDA_EMFILE  -24
#define BURMALDA_EPIPE  -32
#define BURMALDA_ERANGE  -34
#define BURMALDA_ENOTEMPTY  -39
#define BURMALDA_ELOOP  -40
#define BURMALDA_ENOSYS   38
#define BURMALDA_EBADF     9
#define BURMALDA_EINVAL   22
#define BURMALDA_EFAULT   14
#define BURMALDA_ENOMEM   12
#define BURMALDA_EPERM     1
#define BURMALDA_ENOTTY   25
#define BURMALDA_ENOTDIR  20
#define BURMALDA_ENOEXEC   8
#define BURMALDA_ENOENT    2
#define BURMALDA_EAGAIN   11
#define BURMALDA_EACCES   13
#define BURMALDA_EEXIST   17
#define BURMALDA_ENOSPC   28
#define BURMALDA_ENAMETOOLONG 36
#define BURMALDA_EAFNOSUPPORT 97
#define BURMALDA_ECONNREFUSED 111

/* arch_prctl subcodes (x86_64) */
#define BURMALDA_ARCH_SET_FS     0x1002
#define BURMALDA_ARCH_GET_FS     0x1003
#define BURMALDA_ARCH_SET_GS     0x1001
#define BURMALDA_ARCH_GET_GS     0x1004

/* -----------------------------------------------------------------------
 * Fault message layout helpers (x86_64).
 *
 * When the kernel delivers an UnknownSyscall fault the IPC message
 * registers are laid out as:
 *
 *   MR  0  RAX  — syscall number (Linux ABI)
 *   MR  1  RBX
 *   MR  2  RCX
 *   MR  3  RDX  — arg2
 *   MR  4  RSI  — arg1
 *   MR  5  RDI  — arg0
 *   MR  6  RBP
 *   MR  7  R8   — arg4
 *   MR  8  R9   — arg5
 *   MR  9  R10  — arg3
 *   MR 10  R11
 *   MR 11..14   R12–R15
 *   MR 15  FaultIP
 *   MR 16  SP
 *   MR 17  FLAGS
 *   MR 18  Syscall  (seL4's own syscall number — not the POSIX nr)
 *
 * On reply, the kernel calls copyMRsFaultReply() which copies MRs 0–17
 * back into the thread's registers.  burmalda must set:
 *   MR  0  (RAX)     = return value
 *   MR 15  (FaultIP) = FaultIP + 2  (advance past the two-byte syscall insn)
 * and leave all other MRs unchanged (they were written by the kernel).
 * ----------------------------------------------------------------------- */

/* Linux x86_64 SysV argument order: rdi, rsi, rdx, r10, r8, r9 */
static inline long burmalda_get_syscall_nr(void)
{
    return (long)seL4_GetMR(seL4_UnknownSyscall_RAX);
}

static inline long burmalda_get_arg0(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_RDI); }
static inline long burmalda_get_arg1(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_RSI); }
static inline long burmalda_get_arg2(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_RDX); }
/* arg3 uses R10 on Linux x86_64 (not RCX, which syscall clobbers) */
static inline long burmalda_get_arg3(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_R10); }
static inline long burmalda_get_arg4(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_R8);  }
static inline long burmalda_get_arg5(void) { return (long)seL4_GetMR(seL4_UnknownSyscall_R9);  }

/* Build a reply message that resumes the thread with `retval` in rax.
 * The other MRs are already in the IPC buffer from the fault receive. */
static inline seL4_MessageInfo_t burmalda_make_reply(long retval)
{
    seL4_Word fip = seL4_GetMR(seL4_UnknownSyscall_FaultIP);
    seL4_SetMR(seL4_UnknownSyscall_RAX,     (seL4_Word)retval);
    seL4_SetMR(seL4_UnknownSyscall_FaultIP,  fip + 2);  /* skip `syscall` insn */
    /* length = seL4_UnknownSyscall_Syscall = 18: covers all GPRs the
     * kernel restores; excludes the read-only Syscall MR (index 18). */
    return seL4_MessageInfo_new(0, 0, 0, seL4_UnknownSyscall_Syscall);
}

#define BURMALDA_SYS_read        0
#define BURMALDA_SYS_write       1
#define BURMALDA_SYS_open        2
#define BURMALDA_SYS_close       3
#define BURMALDA_SYS_stat       4
#define BURMALDA_SYS_rt_sigreturn 15
#define BURMALDA_SYS_fstat       5
#define BURMALDA_SYS_lseek       8
#define BURMALDA_SYS_mmap        9
#define BURMALDA_SYS_mprotect    10
#define BURMALDA_SYS_munmap      11
#define BURMALDA_SYS_brk         12
#define BURMALDA_SYS_rt_sigaction        13
#define BURMALDA_SYS_rt_sigprocmask      14
#define BURMALDA_SYS_ioctl       16
#define BURMALDA_SYS_dup2        33
#define BURMALDA_SYS_getdents64  217
#define BURMALDA_SYS_connect     42
#define BURMALDA_SYS_setrlimit   103
#define BURMALDA_SYS_prctl       157
#define BURMALDA_SYS_reboot      169
#define BURMALDA_SYS_writev      20
#define BURMALDA_SYS_access      21
#define BURMALDA_SYS_openat      257
#define BURMALDA_SYS_pipe        22
#define BURMALDA_SYS_pipe2       293
#define BURMALDA_SYS_poll        7
#define BURMALDA_SYS_getgid      104
#define BURMALDA_SYS_gettid      186
#define BURMALDA_SYS_getpgid     121
#define BURMALDA_SYS_sync        162
#define BURMALDA_SYS_getpid      39
#define BURMALDA_SYS_socket      41
#define BURMALDA_SYS_accept     288 /* accept4 */
#define BURMALDA_SYS_bind        49
#define BURMALDA_SYS_listen      50
#define BURMALDA_SYS_clone       56
#define BURMALDA_SYS_fork        57
#define BURMALDA_SYS_execve      59
#define BURMALDA_SYS_exit        60
#define BURMALDA_SYS_wait4       61
#define BURMALDA_SYS_kill        62
#define BURMALDA_SYS_uname       63
#define BURMALDA_SYS_fcntl       72
#define BURMALDA_SYS_getcwd      79
#define BURMALDA_SYS_chdir       80
#define BURMALDA_SYS_unlink      87
#define BURMALDA_SYS_chmod       90
#define BURMALDA_SYS_umask       95
#define BURMALDA_SYS_getrlimit   97
#define BURMALDA_SYS_getuid      102
#define BURMALDA_SYS_geteuid     107
#define BURMALDA_SYS_getegid     108
#define BURMALDA_SYS_getppid     110
#define BURMALDA_SYS_setsid      112
#define BURMALDA_SYS_setpgid     154
#define BURMALDA_SYS_arch_prctl  158
#define BURMALDA_SYS_tkill       200
#define BURMALDA_SYS_futex       202
#define BURMALDA_SYS_tgkill      234
#define BURMALDA_SYS_set_tid_address 218
#define BURMALDA_SYS_timer_create  222
#define BURMALDA_SYS_timer_settime 223
#define BURMALDA_SYS_timer_delete  226
#define BURMALDA_SYS_clock_gettime 228
#define BURMALDA_SYS_exit_group  231
#define BURMALDA_SYS_pselect6    270
#define BURMALDA_SYS_prlimit64   302
#define BURMALDA_SYS_flock       32
#define BURMALDA_SYS_setrlimit2 160
#define BURMALDA_SYS_reboot_r 169
#define BURMALDA_SYS_prctl_r 157
#define BURMALDA_SYS_gettid_r 186
#define BURMALDA_SYS_getrusage  98
#define BURMALDA_SYS_times      43
#define BURMALDA_SYS_setitimer  38
#define BURMALDA_SYS_sigaltstack 132
#define BURMALDA_SYS_rt_sigsuspend 130
#define BURMALDA_SYS_madvise    28
#define BURMALDA_SYS_fchdir     81
#define BURMALDA_SYS_readlink   89
#define BURMALDA_SYS_dup3       292
#define BURMALDA_SYS_fchmod     91
#define BURMALDA_SYS_statx       332
#define BURMALDA_SYS_sendfile    40
#define BURMALDA_SYS_copy_file_range 326
#define BURMALDA_SYS_nanosleep   35
#define BURMALDA_SYS_clock_nanosleep 230
#define BURMALDA_SYS_waitid       247
#define BURMALDA_SYS_rename       82
#define BURMALDA_SYS_mkdir        83
#define BURMALDA_SYS_rmdir        84
#define BURMALDA_SYS_mkdirat      258
#define BURMALDA_SYS_renameat2    316

/* -----------------------------------------------------------------------
 * Process-manager hooks.
 *
 * POSIX processes run in their own VSpaces and are identified by the
 * badge on their fault endpoint (badge == POSIX pid).  The process
 * manager (root task) registers callbacks for child memory access,
 * page allocation and the process lifecycle; burmalda calls them from
 * its syscall handlers.
 *
 * While the memory hooks are unregistered burmalda falls back to direct
 * dereference (shared-VSpace smoke tests only).
 * ----------------------------------------------------------------------- */

typedef bool (*burmalda_mem_read_fn)(void *ctx, seL4_Word badge,
                                     void *dest, seL4_Word src, seL4_Word len);
typedef bool (*burmalda_mem_write_fn)(void *ctx, seL4_Word badge,
                                      seL4_Word dest, const void *src,
                                      seL4_Word len);

void burmalda_set_child_mem_reader(burmalda_mem_read_fn fn, void *ctx);
void burmalda_set_child_mem_writer(burmalda_mem_write_fn fn, void *ctx);

/* Copy bytes between the root task and a child address space. */
bool burmalda_read_child(seL4_Word badge, void *dest, seL4_Word src,
                         seL4_Word len);
bool burmalda_write_child(seL4_Word badge, seL4_Word dest, const void *src,
                          seL4_Word len);

/* Anonymous-page allocation (mmap/brk).  hint == 0: manager picks
 * (bump); non-zero: map at that exact child vaddr.  Returns child vaddr
 * or 0 on failure. */
typedef seL4_Word (*burmalda_alloc_pages_fn)(void *ctx, seL4_Word badge,
                                             seL4_Word len, seL4_Word hint);
void burmalda_set_page_allocator(burmalda_alloc_pages_fn fn, void *ctx);
seL4_Word burmalda_alloc_child_pages(seL4_Word badge, seL4_Word len,
                                     seL4_Word hint);

/* Full 20-word user-context write (seL4_UserContext layout), optionally
 * resuming the thread.  Used for TLS setup (no resume) and for waking
 * blocked waiters / starting forked children (resume). */
typedef long (*burmalda_write_ctx_fn)(void *ctx, seL4_Word badge,
                                      const seL4_Word *regs20, bool resume);
void burmalda_set_write_ctx_hook(burmalda_write_ctx_fn fn, void *ctx);
long burmalda_write_child_ctx(seL4_Word badge, const seL4_Word *regs20,
                              bool resume);

/* arch_prctl(ARCH_SET_FS, addr) — set the child's fs_base.  Called while
 * the UnknownSyscall fault message is still in the IPC buffer. */
typedef long (*burmalda_set_fs_base_fn)(void *ctx, seL4_Word badge,
                                        seL4_Word addr);
void burmalda_set_fs_base_hook(burmalda_set_fs_base_fn fn, void *ctx);

/* Process lifecycle: fork, execve, exit, wait-reaping.
 * spawn:  duplicate the parent; returns the new badge (0 on failure).
 *         The child is NOT started; the caller resumes it via
 *         write_child_ctx with the parent's registers.
 * exec:   replace the child image (ELF bytes live in the ROOT task),
 *         restart its thread; 0 on success, -1 on failure.
 * exit:   mark the child dead; returns its parent badge (0 if none).
 * dead_child: find an unreaped exited child; returns its badge or 0. */
typedef seL4_Word (*burmalda_spawn_fn)(void *ctx, seL4_Word parent_badge);
typedef long (*burmalda_exec_fn)(void *ctx, seL4_Word badge,
                                 seL4_Word elf_data, seL4_Word elf_size,
                                 const char *const *argv);
typedef seL4_Word (*burmalda_exit_fn)(void *ctx, seL4_Word badge, long status);
typedef seL4_Word (*burmalda_dead_child_fn)(void *ctx, seL4_Word badge,
                                            long *status);

typedef void (*burmalda_reap_fn)(void *ctx, seL4_Word badge);
void burmalda_set_reap_hook(burmalda_reap_fn fn, void *ctx);

/* Fatal-signal termination: suspend the target TCB, mark it exited
 * with the signal number as status, recycle resources.  The manager
 * must also SIGCHLD the parent (burmalda raises it itself). */
typedef void (*burmalda_terminate_fn)(void *ctx, seL4_Word badge, long signo);
void burmalda_set_terminate_hook(burmalda_terminate_fn fn, void *ctx);

/* Serial-IRQ notification cap (root-task slot).  burmalda Ack's it and
 * relies on the bound-notification wakeup to service blocked console
 * reads between fault deliveries. */
void burmalda_set_serial_irq_notif(seL4_CPtr notif);
void burmalda_set_serial_irq_slot(seL4_Word slot);

/* Calibrate the monotonic clock: TSC frequency in Hz (PIT-measured by
 * the process manager at boot).  0/omitted = 1 tick == 1 ns. */
void burmalda_set_time_base(uint64_t tsc_hz);

void burmalda_set_spawn_hook(burmalda_spawn_fn fn, void *ctx);
void burmalda_set_exec_hook(burmalda_exec_fn fn, void *ctx);
void burmalda_set_exit_hook(burmalda_exit_fn fn, void *ctx);
void burmalda_set_dead_child_hook(burmalda_dead_child_fn fn, void *ctx);

void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj);
