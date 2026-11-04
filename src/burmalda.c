/*
 * burmalda — Ferrix POSIX Server
 *
 * This is the userspace POSIX personality for the Ferrix microkernel.
 * It runs as an ordinary seL4 thread (or the root task during early
 * bringup) and receives seL4_Fault_UnknownSyscall faults from every
 * thread that has seL4_TCBFlag_posixSyscalls set.
 *
 * Architecture: x86_64 / Linux syscall ABI.
 *
 * Current milestone (K2 skeleton):
 *   - Dispatch loop: receive fault → dispatch by syscall number → reply.
 *   - Implemented: write (fd 1/2 → serial), read (stub), exit/exit_group,
 *                  getpid.
 *   - Everything else returns -ENOSYS.
 *
 * Future milestones:
 *   - Virtual file-descriptor table.
 *   - rump kernel integration for real FS/net syscalls.
 *   - Signal delivery (rewrite registers before reply).
 *   - Multi-process table (one fault EP per process, muxed here).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <stdio.h>
#include <string.h>

#include <burmalda/protocol.h>

/* -----------------------------------------------------------------------
 * Serial / debug output shim.
 *
 * During early bringup there is no real file-descriptor table.  Writes
 * to fd 1 (stdout) and fd 2 (stderr) go directly to the kernel's debug
 * putchar.  All other fds return EBADF.
 * ----------------------------------------------------------------------- */

#ifdef CONFIG_PRINTING
static void burmalda_putbuf(const char *buf, seL4_Word len)
{
    for (seL4_Word i = 0; i < len; i++) {
        seL4_DebugPutChar(buf[i]);
    }
}
#else
static void burmalda_putbuf(const char *buf, seL4_Word len)
{
    (void)buf; (void)len;
}
#endif

/* -----------------------------------------------------------------------
 * Syscall handlers
 * ----------------------------------------------------------------------- */

/* SYS_write(fd, buf, count) */
static long burmalda_handle_write(void)
{
    long fd          = burmalda_get_arg0();
    seL4_Word buf_addr = (seL4_Word)burmalda_get_arg1();
    long count       = burmalda_get_arg2();

    if (fd != 1 && fd != 2) {
        return -BURMALDA_EBADF;
    }
    if (count < 0) {
        return -BURMALDA_EINVAL;
    }
    /* TODO: validate VSpace mapping before dereferencing. */
    burmalda_putbuf((const char *)buf_addr, (seL4_Word)count);
    return count;
}

/* SYS_read — stub */
static long burmalda_handle_read(void)
{
    return -BURMALDA_ENOSYS;
}

/* SYS_open — stub */
static long burmalda_handle_open(void)
{
    return -BURMALDA_ENOSYS;
}

/* SYS_close — stub */
static long burmalda_handle_close(void)
{
    return -BURMALDA_ENOSYS;
}

/* SYS_getpid — placeholder */
static long burmalda_handle_getpid(void)
{
    return 1;
}

/* SYS_exit / SYS_exit_group — suspend thread by not replying */
#define BURMALDA_NO_REPLY LONG_MIN

static long burmalda_handle_exit(void)
{
    long status = burmalda_get_arg0();
    printf("burmalda: thread called exit(%ld) — suspending\n", status);
    return BURMALDA_NO_REPLY;
}

/* -----------------------------------------------------------------------
 * Dispatch
 * ----------------------------------------------------------------------- */

static long burmalda_dispatch(long nr)
{
    switch (nr) {
    case BURMALDA_SYS_read:        return burmalda_handle_read();
    case BURMALDA_SYS_write:       return burmalda_handle_write();
    case BURMALDA_SYS_open:        return burmalda_handle_open();
    case BURMALDA_SYS_close:       return burmalda_handle_close();
    case BURMALDA_SYS_getpid:      return burmalda_handle_getpid();
    case BURMALDA_SYS_exit:        /* fall through */
    case BURMALDA_SYS_exit_group:  return burmalda_handle_exit();
    default:
        printf("burmalda: unhandled syscall %ld — ENOSYS\n", nr);
        return -BURMALDA_ENOSYS;
    }
}

/* -----------------------------------------------------------------------
 * Main dispatch loop
 * ----------------------------------------------------------------------- */

#ifdef CONFIG_KERNEL_MCS

void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj)
{
    seL4_Word badge = 0;
    seL4_MessageInfo_t info = seL4_Recv(ep, &badge, reply_obj);

    for (;;) {
        if (seL4_MessageInfo_get_label(info) != seL4_Fault_UnknownSyscall) {
            printf("burmalda: unexpected fault label %lu — ignoring\n",
                   (unsigned long)seL4_MessageInfo_get_label(info));
            info = seL4_ReplyRecv(ep,
                                  seL4_MessageInfo_new(0, 0, 0, 0),
                                  &badge, reply_obj);
            continue;
        }

        long nr     = burmalda_get_syscall_nr();
        long retval = burmalda_dispatch(nr);

        if (retval == BURMALDA_NO_REPLY) {
            info = seL4_Recv(ep, &badge, reply_obj);
        } else {
            info = seL4_ReplyRecv(ep, burmalda_make_reply(retval),
                                  &badge, reply_obj);
        }
    }
}

#else /* non-MCS */

void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj)
{
    (void)reply_obj;

    for (;;) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(ep, &badge);

        if (seL4_MessageInfo_get_label(info) != seL4_Fault_UnknownSyscall) {
            printf("burmalda: unexpected fault label %lu — ignoring\n",
                   (unsigned long)seL4_MessageInfo_get_label(info));
            continue;
        }

        long nr     = burmalda_get_syscall_nr();
        long retval = burmalda_dispatch(nr);

        if (retval != BURMALDA_NO_REPLY) {
            seL4_Reply(burmalda_make_reply(retval));
        }
    }
}

#endif /* CONFIG_KERNEL_MCS */
