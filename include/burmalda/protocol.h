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

#include <sel4/sel4.h>
#include <sel4/sel4_arch/constants.h>  /* seL4_UnknownSyscall_* */

/* -----------------------------------------------------------------------
 * Linux x86_64 syscall numbers (subset implemented in this skeleton).
 * Source: arch/x86/entry/syscalls/syscall_64.tbl in the Linux kernel.
 * ----------------------------------------------------------------------- */
#define BURMALDA_SYS_read        0
#define BURMALDA_SYS_write       1
#define BURMALDA_SYS_open        2
#define BURMALDA_SYS_close       3
#define BURMALDA_SYS_exit        60
#define BURMALDA_SYS_getpid      39
#define BURMALDA_SYS_exit_group  231

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

/* Linux errno values (negated on return: return -ENOSYS etc.) */
#define BURMALDA_ENOSYS   38
#define BURMALDA_EBADF     9
#define BURMALDA_EINVAL   22
#define BURMALDA_EFAULT   14
