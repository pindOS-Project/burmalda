/*
 * burmalda — Ferrix POSIX Server
 *
 * The userspace POSIX personality for the Ferrix microkernel.  Threads
 * flagged seL4_TCBFlag_posixSyscalls fault to the shared POSIX endpoint
 * with a badge equal to their POSIX pid; burmalda dispatches the Linux
 * x86_64 syscall carried in the fault message and replies.
 *
 * Implemented subsystems:
 *   - process table (fork / clone / execve / exit / wait4 / waitid),
 *     fatal-signal termination, backed by hooks in ferrix-init
 *   - dynamic RAM filesystem (O_CREAT/write/unlink/getdents64/stat/
 *     statx/fstat/newfstatat/lseek), seeded from an embedded newc-cpio
 *     archive plus read-only ELF blobs
 *   - pipes (ring buffers), console terminal ioctls (termios/winsize)
 *   - memory management (mmap/brk/mprotect/munmap via the manager)
 *   - TLS (arch_prctl), blocking console read (serial-IRQ wakeup with
 *     deferred reply completion), nanosleep/setitimer timers,
 *     sendfile/copy_file_range, poll/pselect6 readiness, signal
 *     delivery (sigaction/procmask/sigreturn frames, fatal kill)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <burmalda/protocol.h>

/* Embedded blobs (see ferrix-init/src/*_embed.S). */
extern const uint8_t dinit_elf_start[];
extern const uint8_t dinit_elf_end[];
extern const uint8_t halt_elf_start[];
extern const uint8_t halt_elf_end[];
extern const uint8_t idle_elf_start[];
extern const uint8_t idle_elf_end[];
extern const uint8_t fsh_elf_start[];
extern const uint8_t fsh_elf_end[];
extern const uint8_t busybox_elf_start[];
extern const uint8_t busybox_elf_end[];
extern const uint8_t rootfs_cpio_start[];
extern const uint8_t rootfs_cpio_end[];

/* -----------------------------------------------------------------------
 * Serial / debug output shim.
 * ----------------------------------------------------------------------- */

static void burmalda_putbuf(const char *buf, seL4_Word len)
{
    for (seL4_Word i = 0; i < len; i++) {
        seL4_DebugPutChar(buf[i]);
    }
}

static void burmalda_put_hex(seL4_Word value)
{
    static const char digits[] = "0123456789abcdef";
    char buffer[2 * sizeof(value)];
    for (seL4_Word i = 0; i < sizeof(value) * 2; i++) {
        seL4_Word shift = (sizeof(value) * 2 - i - 1) * 4;
        buffer[i] = digits[(value >> shift) & 0xf];
    }
    burmalda_putbuf(buffer, sizeof(buffer));
}

static void burmalda_put_dec(long value)
{
    char buf[21];
    int i = (int)sizeof(buf);
    bool neg = value < 0;
    unsigned long u = neg ? (unsigned long)(-value) : (unsigned long)value;
    do { buf[--i] = (char)('0' + (u % 10)); u /= 10; } while (u > 0);
    if (neg) buf[--i] = '-';
    burmalda_putbuf(buf + i, sizeof(buf) - i);
}

static void burmalda_report_unexpected_fault(seL4_MessageInfo_t info)
{
    seL4_Word label = seL4_MessageInfo_get_label(info);
    burmalda_putbuf("burmalda: unexpected fault label=0x", 35);
    burmalda_put_hex(label);
    if (label == seL4_Fault_VMFault) {
        burmalda_putbuf(" ip=0x", 6);
        burmalda_put_hex(seL4_GetMR(seL4_VMFault_IP));
        burmalda_putbuf(" addr=0x", 8);
        burmalda_put_hex(seL4_GetMR(seL4_VMFault_Addr));
        burmalda_putbuf(" fsr=0x", 7);
        burmalda_put_hex(seL4_GetMR(seL4_VMFault_FSR));
    }
    burmalda_putbuf("\n", 1);
}

/* -----------------------------------------------------------------------
 * Process-manager hooks.
 * ----------------------------------------------------------------------- */

typedef bool (*burmalda_mem_read_fn)(void *ctx, seL4_Word badge,
                                     void *dest, seL4_Word src, seL4_Word len);
typedef bool (*burmalda_mem_write_fn)(void *ctx, seL4_Word badge,
                                      seL4_Word dest, const void *src,
                                      seL4_Word len);
typedef seL4_Word (*burmalda_alloc_pages_fn)(void *ctx, seL4_Word badge,
                                             seL4_Word len, seL4_Word hint);
typedef long (*burmalda_write_ctx_fn)(void *ctx, seL4_Word badge,
                                      const seL4_Word *regs20, bool resume);
typedef long (*burmalda_set_fs_base_fn)(void *ctx, seL4_Word badge,
                                        seL4_Word addr);
typedef seL4_Word (*burmalda_spawn_fn)(void *ctx, seL4_Word parent_badge);
typedef long (*burmalda_exec_fn)(void *ctx, seL4_Word badge,
                                 seL4_Word elf_data, seL4_Word elf_size,
                                 const char *const *argv);
typedef seL4_Word (*burmalda_exit_fn)(void *ctx, seL4_Word badge, long status);
typedef seL4_Word (*burmalda_dead_child_fn)(void *ctx, seL4_Word badge,
                                            long *status);
typedef void (*burmalda_reap_fn)(void *ctx, seL4_Word badge);
typedef void (*burmalda_terminate_fn)(void *ctx, seL4_Word badge, long signo);

static burmalda_mem_read_fn _mem_reader;
static void *_mem_reader_ctx;
static burmalda_mem_write_fn _mem_writer;
static void *_mem_writer_ctx;
static burmalda_alloc_pages_fn _page_alloc;
static void *_page_alloc_ctx;
static burmalda_write_ctx_fn _write_ctx;
static void *_write_ctx_ctx;
static burmalda_set_fs_base_fn _set_fs_base;
static void *_set_fs_base_ctx;
static burmalda_spawn_fn _spawn;
static void *_spawn_ctx;
static burmalda_exec_fn _exec;
static void *_exec_ctx;
static burmalda_exit_fn _exit_fn;
static void *_exit_ctx;
static burmalda_dead_child_fn _dead_child;
static void *_dead_child_ctx;
static burmalda_reap_fn _reap;
static void *_reap_ctx;
static burmalda_terminate_fn _terminate;
static void *_terminate_ctx;

void burmalda_set_child_mem_reader(burmalda_mem_read_fn fn, void *ctx)
{ _mem_reader = fn; _mem_reader_ctx = ctx; }

void burmalda_set_child_mem_writer(burmalda_mem_write_fn fn, void *ctx)
{ _mem_writer = fn; _mem_writer_ctx = ctx; }

void burmalda_set_page_allocator(burmalda_alloc_pages_fn fn, void *ctx)
{ _page_alloc = fn; _page_alloc_ctx = ctx; }

void burmalda_set_write_ctx_hook(burmalda_write_ctx_fn fn, void *ctx)
{ _write_ctx = fn; _write_ctx_ctx = ctx; }

void burmalda_set_fs_base_hook(burmalda_set_fs_base_fn fn, void *ctx)
{ _set_fs_base = fn; _set_fs_base_ctx = ctx; }

void burmalda_set_spawn_hook(burmalda_spawn_fn fn, void *ctx)
{ _spawn = fn; _spawn_ctx = ctx; }

void burmalda_set_exec_hook(burmalda_exec_fn fn, void *ctx)
{ _exec = fn; _exec_ctx = ctx; }

void burmalda_set_exit_hook(burmalda_exit_fn fn, void *ctx)
{ _exit_fn = fn; _exit_ctx = ctx; }

void burmalda_set_dead_child_hook(burmalda_dead_child_fn fn, void *ctx)
{ _dead_child = fn; _dead_child_ctx = ctx; }

void burmalda_set_reap_hook(burmalda_reap_fn fn, void *ctx)
{ _reap = fn; _reap_ctx = ctx; }

void burmalda_set_terminate_hook(burmalda_terminate_fn fn, void *ctx)
{ _terminate = fn; _terminate_ctx = ctx; }

bool burmalda_read_child(seL4_Word badge, void *dest, seL4_Word src,
                         seL4_Word len)
{
    if (_mem_reader != NULL)
        return _mem_reader(_mem_reader_ctx, badge, dest, src, len);
    memcpy(dest, (const void *)src, len);
    return true;
}

bool burmalda_write_child(seL4_Word badge, seL4_Word dest, const void *src,
                          seL4_Word len)
{
    if (_mem_writer != NULL)
        return _mem_writer(_mem_writer_ctx, badge, dest, src, len);
    memcpy((void *)dest, src, len);
    return true;
}

seL4_Word burmalda_alloc_child_pages(seL4_Word badge, seL4_Word len,
                                     seL4_Word hint)
{
    if (_page_alloc != NULL)
        return _page_alloc(_page_alloc_ctx, badge, len, hint);
    return 0;
}

long burmalda_write_child_ctx(seL4_Word badge, const seL4_Word *regs20,
                              bool resume)
{
    if (_write_ctx != NULL)
        return _write_ctx(_write_ctx_ctx, badge, regs20, resume);
    return -1;
}

/* Serial-IRQ wakeup channel. */
static seL4_CPtr _serial_irq_notif = seL4_CapNull;
static seL4_Word _serial_irq_slot = 0;

void burmalda_set_serial_irq_notif(seL4_CPtr notif)
{ _serial_irq_notif = notif; }

void burmalda_set_serial_irq_slot(seL4_Word slot)
{ _serial_irq_slot = slot; }

/* -----------------------------------------------------------------------
 * Reply bookkeeping + fault snapshot.
 * ----------------------------------------------------------------------- */

static bool _reply_raw;
static bool _mrs_modified;
static seL4_Word _fault_mrs[18];

#define BURMALDA_NO_REPLY LONG_MIN

static void save_fault_mrs(seL4_Word *out)
{
    for (int i = 0; i < 18; i++) out[i] = seL4_GetMR(i);
}

/* Build a 20-word UserContext from a saved fault MR set. */
static void ctx_from_mrs(const seL4_Word *mrs, seL4_Word rax,
                         seL4_Word *out20)
{
    out20[0]  = mrs[seL4_UnknownSyscall_FaultIP] + 2;
    out20[1]  = mrs[seL4_UnknownSyscall_SP];
    out20[2]  = mrs[seL4_UnknownSyscall_FLAGS];
    out20[3]  = rax;
    out20[4]  = mrs[seL4_UnknownSyscall_RBX];
    out20[5]  = mrs[seL4_UnknownSyscall_RCX];
    out20[6]  = mrs[seL4_UnknownSyscall_RDX];
    out20[7]  = mrs[seL4_UnknownSyscall_RSI];
    out20[8]  = mrs[seL4_UnknownSyscall_RDI];
    out20[9]  = mrs[seL4_UnknownSyscall_RBP];
    out20[10] = mrs[seL4_UnknownSyscall_R8];
    out20[11] = mrs[seL4_UnknownSyscall_R9];
    out20[12] = mrs[seL4_UnknownSyscall_R10];
    out20[13] = mrs[seL4_UnknownSyscall_R11];
    out20[14] = mrs[seL4_UnknownSyscall_R12];
    out20[15] = mrs[seL4_UnknownSyscall_R13];
    out20[16] = mrs[seL4_UnknownSyscall_R14];
    out20[17] = mrs[seL4_UnknownSyscall_R15];
    out20[18] = 0;
    out20[19] = 0;
}

/* -----------------------------------------------------------------------
 * Time.
 * --------------------------------------------------------------------- */

static uint64_t _tsc_hz = 0;

void burmalda_set_time_base(uint64_t tsc_hz)
{
    if (tsc_hz > 0) _tsc_hz = tsc_hz;
}

static uint64_t tsc_now(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static uint64_t tsc_now_ns(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t t = ((uint64_t)hi << 32) | lo;
    if (_tsc_hz == 0) return t;
    uint64_t sec = t / _tsc_hz;
    uint64_t rem = t % _tsc_hz;
    return sec * 1000000000ULL + (rem * 1000000000ULL) / _tsc_hz;
}

/* -----------------------------------------------------------------------
 * Per-process state.
 * ----------------------------------------------------------------------- */

#define BURMALDA_MAX_PROCS 8
#define BURMALDA_MAX_FDS   64
#define BRK_BASE 0x10000000UL
#define BRK_LIMIT 0x18000000UL

struct bpipe {
    uint8_t buf[4096];
    seL4_Word r, len;
    bool rd_closed, wr_closed;
    int readers, writers;
};

enum fd_kind { FD_CONSOLE = 0, FD_FILE, FD_PIPE_RD, FD_PIPE_WR };

struct rfile;

struct bfile {
    bool open;
    bool is_dir;
    struct rfile *f;
    seL4_Word off;
    enum fd_kind kind;
    struct bpipe *pipe;
};

struct sigent {
    seL4_Word handler;
    seL4_Word flags;
    seL4_Word restorer;
    seL4_Word mask;
};

struct btimer {
    bool armed;
    bool used;
    uint64_t deadline;
    seL4_Word signo;             /* 0 = sleeper (no signal) */
};

struct bproc {
    bool used;
    seL4_Word badge;
    seL4_Word ppid;
    seL4_Word brk;
    struct bfile fds[BURMALDA_MAX_FDS];

    struct sigent sigs[65];
    seL4_Word blocked_mask;
    seL4_Word pending_mask;
    seL4_Word sigchld_pid;
    seL4_Word sigchld_status;

    bool in_signal;
    seL4_Word saved_mrs[18];
    long saved_rax;

    struct btimer timers[4];
};

static struct bpipe _pipes[8];
static int _pipes_used = 0;

static struct bproc _bprocs[BURMALDA_MAX_PROCS];

static struct bproc *bproc_get(seL4_Word badge, bool create)
{
    for (int i = 0; i < BURMALDA_MAX_PROCS; i++) {
        if (_bprocs[i].used && _bprocs[i].badge == badge) return &_bprocs[i];
    }
    if (!create) return NULL;
    for (int i = 0; i < BURMALDA_MAX_PROCS; i++) {
        if (!_bprocs[i].used) {
            memset(&_bprocs[i], 0, sizeof(_bprocs[i]));
            _bprocs[i].used = true;
            _bprocs[i].badge = badge;
            return &_bprocs[i];
        }
    }
    return NULL;
}

static void bproc_reset(seL4_Word badge)
{
    struct bproc *bp = bproc_get(badge, false);
    if (bp != NULL) {
        bp->brk = 0;
        memset(bp->fds, 0, sizeof(bp->fds));
        memset(bp->sigs, 0, sizeof(bp->sigs));
        bp->blocked_mask = 0;
        bp->pending_mask = 0;
        bp->in_signal = false;
    }
}

/* -----------------------------------------------------------------------
 * Deferred-state + signal machinery.
 * ----------------------------------------------------------------------- */

static bool _pending_wait_valid;
static seL4_Word _pending_parent;
static seL4_Word _pending_wstatus;
static seL4_Word _pending_mrs[18];

static bool _pending_read_valid;
static seL4_Word _pending_read_badge;
static seL4_Word _pending_read_buf;
static seL4_Word _pending_read_len;
static seL4_Word _pending_read_mrs[18];

static bool _sleep_active;
static struct bproc *_sleep_proc;
static seL4_Word _sleep_mrs[18];


#define SI_USER_CODE 0
#define CLD_EXITED_CODE 1

/* Deliver one pending unblocked signal by rewriting the fault-message
 * registers to enter its SA_SIGINFO handler with a Linux-style frame. */
static bool burmalda_deliver_signal(struct bproc *bp, seL4_Word badge,
                                    seL4_Word effective_mask)
{
    if (bp == NULL) return false;

    seL4_Word deliverable = bp->pending_mask & ~effective_mask;
    for (int signo = 1; signo <= 64; signo++) {
        if (!(deliverable & (1UL << (signo - 1)))) continue;
        if (bp->sigs[signo].handler <= 1) continue;

        struct sigent *se = &bp->sigs[signo];

        bp->in_signal = true;
        for (int i = 0; i < 18; i++) bp->saved_mrs[i] = seL4_GetMR(i);
        bp->saved_rax = -4;

        seL4_Word rsp = seL4_GetMR(seL4_UnknownSyscall_SP);
        seL4_Word uc_addr  = (rsp - 128 - 936 - 256) & ~0xfUL;
        seL4_Word si_addr  = uc_addr + 944;
        seL4_Word entry    = (uc_addr - 8) & ~0xfUL;

        uint8_t si[128];
        memset(si, 0, sizeof(si));
        uint32_t signo32 = (uint32_t)signo;
        uint32_t code32 = (signo == 17) ? CLD_EXITED_CODE : SI_USER_CODE;
        memcpy(si + 0, &signo32, 4);
        memcpy(si + 8, &code32, 4);
        uint32_t pid32 = (uint32_t)bp->sigchld_pid;
        uint32_t st32  = (uint32_t)bp->sigchld_status;
        memcpy(si + 16, &pid32, 4);
        memcpy(si + 24, &st32, 4);
        if (!burmalda_write_child(badge, si_addr, si, sizeof(si))) {
            bp->in_signal = false;
            continue;
        }

        uint8_t uc[936];
        memset(uc, 0, sizeof(uc));
        seL4_Word ucm = bp->blocked_mask | (1UL << (signo - 1));
        memcpy(uc + 296, &ucm, sizeof(ucm));
        if (!burmalda_write_child(badge, uc_addr, uc, sizeof(uc))) {
            bp->in_signal = false;
            continue;
        }

        if (!burmalda_write_child(badge, entry, &se->restorer,
                                  sizeof(se->restorer))) {
            bp->in_signal = false;
            continue;
        }

        seL4_SetMR(seL4_UnknownSyscall_FaultIP, se->handler - 2);
        seL4_SetMR(seL4_UnknownSyscall_SP, entry);
        seL4_SetMR(seL4_UnknownSyscall_RDI, (seL4_Word)signo);
        seL4_SetMR(seL4_UnknownSyscall_RSI, si_addr);
        seL4_SetMR(seL4_UnknownSyscall_RDX, uc_addr);

        bp->pending_mask &= ~(1UL << (signo - 1));
        bp->blocked_mask = ucm;
        _mrs_modified = true;
        return true;
    }
    return false;
}

/* -----------------------------------------------------------------------
 * RAM filesystem (dynamic entries, pool-backed).
 * --------------------------------------------------------------------- */

struct rfile {
    char        name[96];
    bool        is_dir;
    bool        ro;
    uint8_t    *data;
    seL4_Word   len;
    seL4_Word   cap;
};

#define RAMFS_MAX_ENTRIES 256
#define RAMFS_POOL_SIZE   (8 * 1024 * 1024)

static uint8_t   _ramfs_pool[RAMFS_POOL_SIZE];
static seL4_Word _ramfs_used = 0;
static struct rfile _entries[RAMFS_MAX_ENTRIES];
static int _entry_count = 0;

static uint8_t *ramfs_pool_alloc(seL4_Word n)
{
    n = (n + 15) & ~15UL;
    if (_ramfs_used + n > RAMFS_POOL_SIZE) return NULL;
    uint8_t *p = _ramfs_pool + _ramfs_used;
    _ramfs_used += n;
    return p;
}

static struct rfile *ramfs_alloc_entry(const char *path, bool is_dir, bool ro)
{
    if (_entry_count >= RAMFS_MAX_ENTRIES) return NULL;
    if (strlen(path) >= sizeof(_entries[0].name)) return NULL;
    struct rfile *e = &_entries[_entry_count++];
    memset(e, 0, sizeof(*e));
    strcpy(e->name, path);
    e->is_dir = is_dir;
    e->ro = ro;
    return e;
}

static seL4_Word rfile_len(const struct rfile *f)
{
    return f->len;
}

static struct rfile *ramfs_find(const char *path)
{
    char clean[128];
    seL4_Word n = strlen(path);
    while (n > 1 && path[n - 1] == '/') n--;
    if (n >= sizeof(clean)) return NULL;
    memcpy(clean, path, n);
    clean[n] = '\0';
    for (int i = _entry_count - 1; i >= 0; i--) {
        if (_entries[i].name[0] == '\0') continue;
        if (strcmp(_entries[i].name, clean) == 0) return &_entries[i];
    }
    return NULL;
}

static struct rfile *ramfs_child(const char *dirpath, seL4_Word idx)
{
    seL4_Word n = strlen(dirpath);
    if (n > 1 && dirpath[n - 1] == '/') n--;
    seL4_Word count = 0;
    for (int i = 0; i < _entry_count; i++) {
        if (_entries[i].name[0] == '\0') continue;
        if (strcmp(dirpath, "/") == 0) {
            if (_entries[i].name[0] != '/' || _entries[i].name[1] == '\0') continue;
            if (strchr(_entries[i].name + 1, '/') != NULL) continue;
            if (count == idx) return &_entries[i];
            count++;
            continue;
        }
        if (strncmp(_entries[i].name, dirpath, n) != 0) continue;
        if (_entries[i].name[n] != '/') continue;
        if (strchr(_entries[i].name + n + 1, '/') != NULL) continue;
        if (count == idx) return &_entries[i];
        count++;
    }
    return NULL;
}

static void ramfs_load_cpio(const uint8_t *cp, seL4_Word len)
{
    seL4_Word pos = 0;
    int files = 0, dirs = 0;
    while (pos + 110 <= len) {
        if (cp[pos] != '0' || cp[pos + 1] != '7') break;
        seL4_Word f = pos + 6;
        seL4_Word mode = 0, fsize = 0, namesize = 0;
        for (int i = 0; i < 13; i++) {
            uint64_t v = 0;
            for (int k = 0; k < 8; k++) {
                uint8_t c = cp[f + i * 8 + k];
                uint8_t d = (c <= '9') ? (c - '0') : ((c | 0x20) - 'a' + 10);
                v = (v << 4) | (d & 0xf);
            }
            if (i == 1) mode = (seL4_Word)v;
            if (i == 6) fsize = (seL4_Word)v;
            if (i == 11) namesize = (seL4_Word)v;
        }
        f += 13 * 8;
        if (f + namesize > len) break;
        char name[192];
        seL4_Word cplen = (namesize < sizeof(name)) ? namesize : sizeof(name) - 1;
        memcpy(name, cp + f, cplen);
        name[cplen] = '\0';
        f += namesize;
        f = (f + 3) & ~3UL;
        if (strcmp(name, "TRAILER!!!") == 0) break;

        if (!(mode & 0xF000)) {
            pos = f + fsize;
            pos = (pos + 3) & ~3UL;
            continue;
        }
        bool is_dir = ((mode & 0xF000) == 0x4000);

        struct rfile *e = ramfs_alloc_entry(name, is_dir, false);
        if (e == NULL) break;
        if (!is_dir && fsize > 0) {
            uint8_t *buf = ramfs_pool_alloc(fsize);
            if (buf == NULL) break;
            memcpy(buf, cp + f, fsize);
            e->data = buf;
            e->len = fsize;
            e->cap = fsize;
        }
        if (is_dir) dirs++; else files++;

        pos = f + fsize;
        pos = (pos + 3) & ~3UL;
    }
    burmalda_putbuf("burmalda: cpio loaded ", 21);
    burmalda_put_dec(files);
    burmalda_putbuf(" files, ", 8);
    burmalda_put_dec(dirs);
    burmalda_putbuf(" dirs\n", 7);
}

static void ramfs_init(void)
{
    static const char boot_svc[] = "type: internal\ndepends-on: getty\n";
    static const char getty_svc[] = "type: process\ncommand: /bin/fsh\n"
                                    "restart: yes\n";

    struct { const char *name; bool dir; } dirs[] = {
        { "/", true }, { "/etc", true }, { "/etc/dinit.d", true },
        { "/sbin", true }, { "/dev", true }, { "/run", true },
        { "/tmp", true }, { "/bin", true },
    };
    for (seL4_Word i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        ramfs_alloc_entry(dirs[i].name, true, true);
    }

    struct rfile *e = ramfs_alloc_entry("/etc/dinit.d/boot", false, false);
    e->data = (uint8_t *)boot_svc;  e->len = sizeof(boot_svc) - 1; e->cap = 0;
    e = ramfs_alloc_entry("/etc/dinit.d/getty", false, false);
    e->data = (uint8_t *)getty_svc; e->len = sizeof(getty_svc) - 1; e->cap = 0;

    e = ramfs_alloc_entry("/dev/console", false, false);
    e->data = (uint8_t *)""; e->len = 0; e->cap = 0;
    e = ramfs_alloc_entry("/dev/null", false, false);
    e->data = (uint8_t *)""; e->len = 0; e->cap = 0;

    e = ramfs_alloc_entry("/sbin/dinit", false, true);
    e->data = (uint8_t *)dinit_elf_start;
    e->len = (seL4_Word)(dinit_elf_end - dinit_elf_start); e->cap = e->len;
    e = ramfs_alloc_entry("/sbin/halt", false, true);
    e->data = (uint8_t *)halt_elf_start;
    e->len = (seL4_Word)(halt_elf_end - halt_elf_start); e->cap = e->len;
    e = ramfs_alloc_entry("/sbin/idle", false, true);
    e->data = (uint8_t *)idle_elf_start;
    e->len = (seL4_Word)(idle_elf_end - idle_elf_start); e->cap = e->len;
    e = ramfs_alloc_entry("/sbin/fsh", false, true);
    e->data = (uint8_t *)fsh_elf_start;
    e->len = (seL4_Word)(fsh_elf_end - fsh_elf_start); e->cap = e->len;
    e = ramfs_alloc_entry("/bin/fsh", false, true);
    e->data = (uint8_t *)fsh_elf_start;
    e->len = (seL4_Word)(fsh_elf_end - fsh_elf_start); e->cap = e->len;
    e = ramfs_alloc_entry("/bin/idle", false, true);
    e->data = (uint8_t *)idle_elf_start;
    e->len = (seL4_Word)(idle_elf_end - idle_elf_start); e->cap = e->len;

    {
        static const char *applets[] = {
            "sh", "echo", "ls", "cat", "sleep", "uname", "true", "false",
            "pwd", "printf", "head", "wc", "rm", "cp", "mkdir", "rmdir",
            "stat", "touch", "clear", "sync", "dd", "date", "test",
        };
        for (seL4_Word i = 0; i < sizeof(applets) / sizeof(applets[0]); i++) {
            char apath[64];
            apath[0] = '/'; apath[1] = 'b'; apath[2] = 'i'; apath[3] = 'n'; apath[4] = '/';
            seL4_Word j = 0;
            for (; applets[i][j] != '\0'; j++) apath[5 + j] = applets[i][j];
            apath[5 + j] = '\0';
            e = ramfs_alloc_entry(apath, false, true);
            e->data = (uint8_t *)busybox_elf_start;
            e->len = (seL4_Word)(busybox_elf_end - busybox_elf_start);
            e->cap = e->len;
        }
    }

    ramfs_load_cpio(rootfs_cpio_start,
                    (seL4_Word)(rootfs_cpio_end - rootfs_cpio_start));
}

/* -----------------------------------------------------------------------
 * fd helpers
 * --------------------------------------------------------------------- */

static long fd_read_buffered(seL4_Word badge, struct bproc *bp, long fd,
                             uint8_t *out, seL4_Word n)
{
    if (fd == 0) return 0;
    if (fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) return -1;
    struct bfile *bf = &bp->fds[fd];
    if (bf->kind == FD_PIPE_RD) {
        struct bpipe *pp = bf->pipe;
        if (pp->len == 0) return (pp->wr_closed) ? 0 : -1;
        seL4_Word k = (n < pp->len) ? n : pp->len;
        k = (k > 4096 - pp->r) ? (4096 - pp->r) : k;
        memcpy(out, pp->buf + pp->r, k);
        pp->r = (pp->r + k) % 4096;
        pp->len -= k;
        return (long)k;
    }
    if (bf->is_dir || bf->f->data == NULL) return 0;
    seL4_Word left = rfile_len(bf->f) - bf->off;
    seL4_Word k = (n < left) ? n : left;
    memcpy(out, bf->f->data + bf->off, k);
    bf->off += k;
    return (long)k;
}

static long fd_write_buffered(seL4_Word badge, struct bproc *bp, long fd,
                              const uint8_t *in, seL4_Word n)
{
    if (fd == 1 || fd == 2) {
        burmalda_putbuf((const char *)in, n);
        return (long)n;
    }
    if (fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) return -1;
    struct bfile *bf = &bp->fds[fd];
    if (bf->kind == FD_FILE && bf->f != NULL) {
        struct rfile *f = bf->f;
        seL4_Word end = bf->off + n;
        if (end > f->cap) {
            seL4_Word ncap = (end > 2 * f->cap) ? end : 2 * f->cap + 64;
            uint8_t *nd = ramfs_pool_alloc(ncap);
            if (nd == NULL) return -1;
            if (f->data != NULL && f->len > 0) memcpy(nd, f->data, f->len);
            f->data = nd;
            f->cap = ncap;
        }
        memcpy(f->data + bf->off, in, n);
        if (end > f->len) f->len = end;
        bf->off = end;
        return (long)n;
    }
    return -1;
}

/* -----------------------------------------------------------------------
 * Deferred completion (called from the main loop).
 * --------------------------------------------------------------------- */

static bool burmalda_complete_deferred_read(void)
{
    if (!_pending_read_valid) return false;
    char c;
    if (!seL4_DebugTryGetChar(&c)) return false;

    long rax;
    if (burmalda_write_child(_pending_read_badge, _pending_read_buf, &c, 1)) {
        rax = 1;
    } else {
        rax = -BURMALDA_EFAULT;
    }
    seL4_Word ctx20[20];
    ctx_from_mrs(_pending_read_mrs, (seL4_Word)rax, ctx20);
    _pending_read_valid = false;
    burmalda_write_child_ctx(_pending_read_badge, ctx20, true);
    return true;
}

static void burmalda_complete_sleeps(void)
{
    if (!_sleep_active) return;
    uint64_t now = tsc_now();
    for (int i = 0; i < 4; i++) {
        if (_sleep_proc->timers[i].used && _sleep_proc->timers[i].armed &&
            (int64_t)(now - _sleep_proc->timers[i].deadline) >= 0) {
            _sleep_proc->timers[i].used = false;
            _sleep_proc->timers[i].armed = false;
            seL4_Word ctx20[20];
            ctx_from_mrs(_sleep_mrs, 0, ctx20);
            burmalda_write_child_ctx(_sleep_proc->badge, ctx20, true);
            _sleep_active = false;
            return;
        }
    }
}

static void burmalda_timer_check(struct bproc *bp)
{
    if (bp == NULL) return;
    uint64_t now = tsc_now();
    for (int i = 0; i < 4; i++) {
        if (bp->timers[i].armed && bp->timers[i].used &&
            (int64_t)(now - bp->timers[i].deadline) >= 0) {
            bp->timers[i].armed = false;
            if (bp->timers[i].signo == 0) continue;
            seL4_Word sig = bp->timers[i].signo;
            bp->pending_mask |= (1UL << (sig - 1));
        }
    }
}

/* -----------------------------------------------------------------------
 * Path / fd helpers
 * --------------------------------------------------------------------- */

static bool read_child_str(seL4_Word badge, seL4_Word addr,
                           char *out, seL4_Word out_len)
{
    if (addr == 0) return false;
    seL4_Word i = 0;
    for (; i + 1 < out_len; i++) {
        if (!burmalda_read_child(badge, out + i, addr + i, 1)) return false;
        if (out[i] == '\0') return true;
    }
    out[i] = '\0';
    return false;
}

static int alloc_fd(struct bproc *bp)
{
    for (int fd = 3; fd < BURMALDA_MAX_FDS; fd++) {
        if (!bp->fds[fd].open) return fd;
    }
    return -1;
}

static void fill_stat(const struct rfile *f, uint8_t out[144])
{
    memset(out, 0, 144);
    uint64_t dev = 0x1000, ino = 1, nlink = 1;
    uint32_t mode = f->is_dir ? 0040755u : 0100644u;
    uint64_t size = rfile_len(f);
    memcpy(out + 0,  &dev, 8);
    memcpy(out + 8,  &ino, 8);
    memcpy(out + 16, &nlink, 8);
    memcpy(out + 24, &mode, 4);
    memcpy(out + 48, &size, 8);
}

/* -----------------------------------------------------------------------
 * Syscall handlers
 * ----------------------------------------------------------------------- */

static long burmalda_handle_write(seL4_Word badge)
{
    long fd          = burmalda_get_arg0();
    seL4_Word buf_addr = (seL4_Word)burmalda_get_arg1();
    long count       = burmalda_get_arg2();

    if (count < 0) return -BURMALDA_EINVAL;

    if (fd >= 3 && fd < BURMALDA_MAX_FDS) {
        struct bproc *bp = bproc_get(badge, false);
        if (bp != NULL && bp->fds[fd].open && bp->fds[fd].kind == FD_PIPE_WR) {
            struct bpipe *p = bp->fds[fd].pipe;
            long done = 0;
            uint8_t kbuf[128];
            seL4_Word left = (seL4_Word)count;
            seL4_Word src = buf_addr;
            while (left > 0) {
                seL4_Word chunk = (left > sizeof(kbuf)) ? sizeof(kbuf) : left;
                if (!burmalda_read_child(badge, kbuf, src, chunk)) {
                    return -BURMALDA_EFAULT;
                }
                for (seL4_Word i = 0; i < chunk; i++) {
                    if (p->len == 4096) break;
                    p->buf[(p->r + p->len) % 4096] = kbuf[i];
                    p->len++;
                    done++;
                }
                src += chunk;
                left -= chunk;
                if (p->len == 4096) break;
            }
            return done;
        }
        if (bp != NULL && bp->fds[fd].open && bp->fds[fd].kind == FD_FILE) {
            struct rfile *f = bp->fds[fd].f;
            seL4_Word end = bp->fds[fd].off + (seL4_Word)count;
            if (strcmp(f->name, "/dev/null") == 0) return count;
            if (f->ro) return -BURMALDA_EACCES;
            if (end > f->cap) {
                seL4_Word ncap = (end > 2 * f->cap) ? end : 2 * f->cap + 64;
                uint8_t *nd = ramfs_pool_alloc(ncap);
                if (nd == NULL) return -BURMALDA_ENOSPC;
                if (f->data != NULL && f->len > 0) memcpy(nd, f->data, f->len);
                f->data = nd;
                f->cap = ncap;
            }
            uint8_t kbuf[128];
            seL4_Word left = (seL4_Word)count, src = buf_addr, dst = bp->fds[fd].off;
            while (left > 0) {
                seL4_Word chunk = (left > sizeof(kbuf)) ? sizeof(kbuf) : left;
                if (!burmalda_read_child(badge, kbuf, src, chunk)) {
                    return -BURMALDA_EFAULT;
                }
                memcpy(f->data + dst, kbuf, chunk);
                dst += chunk; src += chunk; left -= chunk;
            }
            if (end > f->len) f->len = end;
            return count;
        }
    }
    if (fd != 1 && fd != 2) {
        return -BURMALDA_EBADF;
    }
    if (count > 0) {
        uint8_t kbuf[128];
        seL4_Word left = (seL4_Word)count;
        seL4_Word src  = buf_addr;
        while (left > 0) {
            seL4_Word chunk = (left > sizeof(kbuf)) ? sizeof(kbuf) : left;
            if (!burmalda_read_child(badge, kbuf, src, chunk)) {
                return -BURMALDA_EFAULT;
            }
            burmalda_putbuf((const char *)kbuf, chunk);
            src  += chunk;
            left -= chunk;
        }
    }
    return count;
}

static long burmalda_handle_writev(seL4_Word badge)
{
    long fd       = burmalda_get_arg0();
    seL4_Word iov = (seL4_Word)burmalda_get_arg1();
    long iovcnt   = burmalda_get_arg2();

    if (fd != 1 && fd != 2) return -BURMALDA_EBADF;
    if (iovcnt < 0 || iovcnt > 1024) return -BURMALDA_EINVAL;

    long done = 0;
    for (long i = 0; i < iovcnt; i++) {
        seL4_Word entry[2];
        if (!burmalda_read_child(badge, entry, iov + i * sizeof(entry),
                                 sizeof(entry))) {
            return (done > 0) ? done : -BURMALDA_EFAULT;
        }
        seL4_Word base = entry[0];
        seL4_Word len  = entry[1];
        while (len > 0) {
            uint8_t kbuf[128];
            seL4_Word chunk = (len > sizeof(kbuf)) ? sizeof(kbuf) : len;
            if (!burmalda_read_child(badge, kbuf, base, chunk)) {
                return (done > 0) ? done : -BURMALDA_EFAULT;
            }
            burmalda_putbuf((const char *)kbuf, chunk);
            base += chunk;
            len  -= chunk;
            done += (long)chunk;
        }
    }
    return done;
}

static long burmalda_handle_openat(seL4_Word badge, bool at)
{
    seL4_Word pathp = at ? (seL4_Word)burmalda_get_arg1()
                         : (seL4_Word)burmalda_get_arg0();
    long flags = at ? burmalda_get_arg2() : burmalda_get_arg1();
    const bool want_creat = (flags & 0x40) != 0;

    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) {
        return -BURMALDA_EFAULT;
    }

    struct rfile *f = NULL;
    if (path[0] == '/') {
        f = ramfs_find(path);
    } else if (at) {
        long dirfd = burmalda_get_arg0();
        struct bproc *bpd = bproc_get(badge, false);
        if (bpd != NULL && dirfd >= 3 && dirfd < BURMALDA_MAX_FDS &&
            bpd->fds[dirfd].open && bpd->fds[dirfd].is_dir) {
            char full[192];
            const char *dir = bpd->fds[dirfd].f->name;
            seL4_Word dn = strlen(dir);
            if (dn == 1) dn = 0;
            if (dn + 1 + strlen(path) < sizeof(full)) {
                memcpy(full, dir, dn);
                full[dn] = '/';
                memcpy(full + dn + 1, path, strlen(path) + 1);
                f = ramfs_find(full);
            }
        }
    }
    if (f == NULL) {
        if (!want_creat) return -BURMALDA_ENOENT;
        char full[192];
        if (path[0] == '/') {
            if (strlen(path) >= sizeof(full)) return -BURMALDA_ENAMETOOLONG;
            memcpy(full, path, strlen(path) + 1);
        } else if (at) {
            long dirfd = burmalda_get_arg0();
            struct bproc *bpd = bproc_get(badge, false);
            if (bpd == NULL || dirfd < 3 || dirfd >= BURMALDA_MAX_FDS ||
                !bpd->fds[dirfd].open || !bpd->fds[dirfd].is_dir) {
                return -BURMALDA_ENOENT;
            }
            const char *dir = bpd->fds[dirfd].f->name;
            seL4_Word dn = strlen(dir);
            if (dn == 1) dn = 0;
            if (dn + 1 + strlen(path) >= sizeof(full)) {
                return -BURMALDA_ENAMETOOLONG;
            }
            memcpy(full, dir, dn);
            full[dn] = '/';
            memcpy(full + dn + 1, path, strlen(path) + 1);
        } else {
            return -BURMALDA_ENOENT;
        }
        if (ramfs_find(full) != NULL) {
            if (flags & 0x80) return -BURMALDA_EEXIST;
            f = ramfs_find(full);
        } else {
            f = ramfs_alloc_entry(full, false, false);
            if (f == NULL) return -BURMALDA_ENOSPC;
            f->data = NULL;
            f->len = 0;
            f->cap = 0;
        }
    }

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    int fd = alloc_fd(bp);
    if (fd < 0) return -BURMALDA_ENOMEM;

    bp->fds[fd].open = true;
    bp->fds[fd].is_dir = f->is_dir;
    bp->fds[fd].f = f;
    bp->fds[fd].off = 0;
    bp->fds[fd].kind = FD_FILE;
    return fd;
}

static long burmalda_handle_close(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    if (fd >= 0 && fd <= 2) return 0;
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || fd < 0 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) {
        return -BURMALDA_EBADF;
    }
    if (bp->fds[fd].kind == FD_PIPE_RD) bp->fds[fd].pipe->readers--;
    if (bp->fds[fd].kind == FD_PIPE_WR) bp->fds[fd].pipe->writers--;
    bp->fds[fd].open = false;
    return 0;
}

static long burmalda_handle_read(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    seL4_Word buf = (seL4_Word)burmalda_get_arg1();
    long count = burmalda_get_arg2();

    if (fd == 0) {
        if (count <= 0) return -BURMALDA_EINVAL;
        char c;
        if (seL4_DebugTryGetChar(&c)) {
            if (!burmalda_write_child(badge, buf, &c, 1)) {
                return -BURMALDA_EFAULT;
            }
            return 1;
        }
        if (_pending_read_valid) return -BURMALDA_EAGAIN;
        _pending_read_valid = true;
        _pending_read_badge = badge;
        _pending_read_buf = buf;
        _pending_read_len = (seL4_Word)count;
        save_fault_mrs(_pending_read_mrs);
        return BURMALDA_NO_REPLY;
    }
    if (count < 0) return -BURMALDA_EINVAL;

    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) {
        return -BURMALDA_EBADF;
    }
    struct bfile *bf = &bp->fds[fd];
    if (bf->kind == FD_PIPE_RD) {
        struct bpipe *pp = bf->pipe;
        if (pp->len == 0) {
            if (pp->wr_closed) return 0;
            return -BURMALDA_EAGAIN;
        }
        seL4_Word k = ((seL4_Word)count < pp->len) ? (seL4_Word)count : pp->len;
        k = (k > 4096 - pp->r) ? (4096 - pp->r) : k;
        if (!burmalda_write_child(badge, buf, pp->buf + pp->r, k)) {
            return -BURMALDA_EFAULT;
        }
        pp->r = (pp->r + k) % 4096;
        pp->len -= k;
        return (long)k;
    }
    if (bf->is_dir) return -BURMALDA_EINVAL;
    if (bf->f->data == NULL) return 0;

    seL4_Word left = rfile_len(bf->f) - bf->off;
    seL4_Word n = ((seL4_Word)count < left) ? (seL4_Word)count : left;
    if (!burmalda_write_child(badge, buf, bf->f->data + bf->off, n)) {
        return -BURMALDA_EFAULT;
    }
    bf->off += n;
    return (long)n;
}

static long burmalda_handle_lseek(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    long off = burmalda_get_arg1();
    long whence = burmalda_get_arg2();

    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) {
        return -BURMALDA_EBADF;
    }
    struct bfile *bf = &bp->fds[fd];
    seL4_Word newoff;
    switch (whence) {
    case 0: newoff = (seL4_Word)off; break;
    case 1: newoff = bf->off + (seL4_Word)off; break;
    case 2: newoff = rfile_len(bf->f) + (seL4_Word)off; break;
    default: return -BURMALDA_EINVAL;
    }
    if (newoff > rfile_len(bf->f)) return -BURMALDA_EINVAL;
    bf->off = newoff;
    return (long)newoff;
}

static long burmalda_handle_fstat(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    seL4_Word statp = (seL4_Word)burmalda_get_arg1();
    if (fd >= 0 && fd <= 2) return -BURMALDA_EINVAL;
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) {
        return -BURMALDA_EBADF;
    }
    uint8_t st[144];
    fill_stat(bp->fds[fd].f, st);
    if (!burmalda_write_child(badge, statp, st, sizeof(st))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_newfstatat(seL4_Word badge, bool at)
{
    seL4_Word pathp = at ? (seL4_Word)burmalda_get_arg1()
                         : (seL4_Word)burmalda_get_arg0();
    seL4_Word statp = at ? (seL4_Word)burmalda_get_arg2()
                         : (seL4_Word)burmalda_get_arg1();
    long flags = at ? burmalda_get_arg3() : 0;

    const struct rfile *f = NULL;
    if (at && (pathp == 0 || (flags & 0x1000))) {
        struct bproc *bp = bproc_get(badge, false);
        long fd = burmalda_get_arg0();
        if (bp == NULL || fd < 3 || !bp->fds[fd].open) return -BURMALDA_EBADF;
        f = bp->fds[fd].f;
    } else {
        char path[128];
        if (!read_child_str(badge, pathp, path, sizeof(path))) {
            return -BURMALDA_EFAULT;
        }
        f = ramfs_find(path);
    }
    if (f == NULL) return -BURMALDA_ENOENT;

    uint8_t st[144];
    fill_stat(f, st);
    if (!burmalda_write_child(badge, statp, st, sizeof(st))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_statx(seL4_Word badge)
{
    seL4_Word pathp = (seL4_Word)burmalda_get_arg1();
    seL4_Word bufp = (seL4_Word)burmalda_get_arg3();

    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) {
        return -BURMALDA_EFAULT;
    }
    struct rfile *f = ramfs_find(path);
    if (f == NULL) return -BURMALDA_ENOENT;

    uint8_t sx[256];
    memset(sx, 0, sizeof(sx));
    uint32_t mask = 0x000007ff;
    uint32_t mode = f->is_dir ? 0040755u : 0100644u;
    uint64_t size = rfile_len(f);
    uint32_t nlink = 1;
    memcpy(sx + 0, &mask, 4);
    memcpy(sx + 32, &nlink, 4);
    memcpy(sx + 44, &mode, 4);
    memcpy(sx + 56, &size, 8);
    uint64_t blocks = (rfile_len(f) + 511) / 512;
    memcpy(sx + 64, &blocks, 8);
    if (!burmalda_write_child(badge, bufp, sx, sizeof(sx))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

struct dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

static long burmalda_handle_getdents64(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    seL4_Word buf = (seL4_Word)burmalda_get_arg1();
    long count = burmalda_get_arg2();

    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) {
        return -BURMALDA_EBADF;
    }
    struct bfile *bf = &bp->fds[fd];
    if (!bf->is_dir) return -BURMALDA_ENOTDIR;

    uint8_t out[512];
    seL4_Word used = 0;
    seL4_Word idx = bf->off;

    for (;;) {
        const struct rfile *c = ramfs_child(bf->f->name, idx);
        if (c == NULL) break;
        idx++;

        const char *base = strrchr(c->name, '/') + 1;
        seL4_Word blen = strlen(base);
        seL4_Word reclen = (offsetof(struct dirent64, d_name) + blen + 1 + 7)
                           & ~7UL;
        if (used + reclen > sizeof(out) || used + (seL4_Word)reclen > (seL4_Word)count) {
            break;
        }
        struct dirent64 *d = (struct dirent64 *)(out + used);
        d->d_ino = 1 + idx;
        d->d_off = (int64_t)(idx + 1);
        d->d_reclen = (uint16_t)reclen;
        d->d_type = c->is_dir ? 4 : 8;
        memcpy(d->d_name, base, blen + 1);
        used += reclen;
    }

    if (used == 0) return 0;
    if (!burmalda_write_child(badge, buf, out, used)) return -BURMALDA_EFAULT;
    bf->off += idx;
    return (long)used;
}

static long burmalda_handle_mmap(seL4_Word badge)
{
    long len = burmalda_get_arg1();
    long fd  = burmalda_get_arg4();

    if (len <= 0) return -BURMALDA_EINVAL;
    if (fd != -1) return -BURMALDA_ENOSYS;

    seL4_Word vaddr = burmalda_alloc_child_pages(badge, (seL4_Word)len, 0);
    if (vaddr == 0) return -BURMALDA_ENOMEM;
    return (long)vaddr;
}

static long burmalda_handle_brk(seL4_Word badge)
{
    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;
    if (bp->brk == 0) bp->brk = BRK_BASE;

    seL4_Word req = (seL4_Word)burmalda_get_arg0();
    if (req == 0) return (long)bp->brk;
    if (req < BRK_BASE || req >= BRK_LIMIT) return (long)bp->brk;

    if (req > bp->brk) {
        if (burmalda_alloc_child_pages(badge, req - bp->brk, bp->brk) == 0) {
            return (long)bp->brk;
        }
    }
    bp->brk = req;
    return (long)bp->brk;
}

static long burmalda_handle_sigaction(seL4_Word badge)
{
    long sig = burmalda_get_arg0();
    seL4_Word act = (seL4_Word)burmalda_get_arg1();
    seL4_Word oldact = (seL4_Word)burmalda_get_arg2();
    long sigsetsize = burmalda_get_arg3();

    if (sig < 1 || sig > 64) return -BURMALDA_EINVAL;
    if (sigsetsize != 8) return -BURMALDA_EINVAL;

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    if (oldact != 0) {
        seL4_Word old[4] = { bp->sigs[sig].handler, bp->sigs[sig].flags,
                             bp->sigs[sig].restorer, bp->sigs[sig].mask };
        if (!burmalda_write_child(badge, oldact, old, sizeof(old))) {
            return -BURMALDA_EFAULT;
        }
    }
    if (act != 0) {
        seL4_Word nw[4];
        if (!burmalda_read_child(badge, nw, act, sizeof(nw))) {
            return -BURMALDA_EFAULT;
        }
        bp->sigs[sig].handler  = nw[0];
        bp->sigs[sig].flags    = nw[1];
        bp->sigs[sig].restorer = nw[2];
        bp->sigs[sig].mask     = nw[3];
    }
    return 0;
}

static long burmalda_handle_sigprocmask(seL4_Word badge)
{
    long how = burmalda_get_arg0();
    seL4_Word setp = (seL4_Word)burmalda_get_arg1();
    seL4_Word oldset = (seL4_Word)burmalda_get_arg2();
    long sigsetsize = burmalda_get_arg3();

    if (sigsetsize != 8) return -BURMALDA_EINVAL;

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    if (oldset != 0) {
        if (!burmalda_write_child(badge, oldset, &bp->blocked_mask,
                                  sizeof(bp->blocked_mask))) {
            return -BURMALDA_EFAULT;
        }
    }
    if (setp != 0) {
        seL4_Word nmask;
        if (!burmalda_read_child(badge, &nmask, setp, sizeof(nmask))) {
            return -BURMALDA_EFAULT;
        }
        switch (how) {
        case 0: bp->blocked_mask |= nmask; break;
        case 1: bp->blocked_mask &= ~nmask; break;
        case 2: bp->blocked_mask = nmask; break;
        default: return -BURMALDA_EINVAL;
        }
    }

    burmalda_deliver_signal(bp, badge, bp->blocked_mask);
    return 0;
}

static long burmalda_handle_dup2(seL4_Word badge)
{
    long oldfd = burmalda_get_arg0();
    long newfd = burmalda_get_arg1();
    if (oldfd < 0 || newfd < 0 || newfd >= BURMALDA_MAX_FDS) {
        return -BURMALDA_EBADF;
    }
    if (oldfd <= 2 || newfd <= 2) return newfd;

    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || oldfd >= BURMALDA_MAX_FDS || !bp->fds[oldfd].open) {
        return -BURMALDA_EBADF;
    }
    bp->fds[newfd] = bp->fds[oldfd];
    return newfd;
}

static long burmalda_handle_pipe2(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg0();
    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    if (_pipes_used >= 8) return -BURMALDA_ENOMEM;
    struct bpipe *p = &_pipes[_pipes_used++];
    p->r = 0; p->len = 0;
    p->rd_closed = p->wr_closed = false;
    p->readers = 1; p->writers = 1;

    int rfd = alloc_fd(bp), wfd = alloc_fd(bp);
    if (rfd < 0 || wfd < 0) return -BURMALDA_ENOMEM;
    bp->fds[rfd] = (struct bfile){ .open = true, .kind = FD_PIPE_RD, .pipe = p };
    bp->fds[wfd] = (struct bfile){ .open = true, .kind = FD_PIPE_WR, .pipe = p };

    int pair[2] = { rfd, wfd };
    if (!burmalda_write_child(badge, out, pair, sizeof(pair))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_unlink(seL4_Word badge)
{
    seL4_Word pathp = (seL4_Word)burmalda_get_arg0();
    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) {
        return -BURMALDA_EFAULT;
    }
    struct rfile *f = ramfs_find(path);
    if (f == NULL) return -BURMALDA_ENOENT;
    if (f->ro || f->is_dir) return -BURMALDA_EPERM;
    f->name[0] = '\0';
    return 0;
}

static long burmalda_handle_fcntl(void)
{
    long cmd = burmalda_get_arg1();
    switch (cmd) {
    case 1: return 2;
    case 2: return 0;
    case 3: return 0;
    case 4: return 0;
    default: return 0;
    }
}

static long burmalda_handle_execve(seL4_Word badge)
{
    seL4_Word pathp = (seL4_Word)burmalda_get_arg0();
    seL4_Word argvp = (seL4_Word)burmalda_get_arg1();

    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) {
        return -BURMALDA_EFAULT;
    }

    const struct rfile *f = ramfs_find(path);
    if (f == NULL || f->is_dir || f->data == NULL) return -BURMALDA_ENOENT;

    static char argv_bufs[8][64];
    static const char *argv_ptrs[9];
    seL4_Word argc = 0;
    for (; argc < 8 && argvp != 0; argc++) {
        seL4_Word sp;
        if (!burmalda_read_child(badge, &sp, argvp + argc * sizeof(sp),
                                 sizeof(sp))) {
            return -BURMALDA_EFAULT;
        }
        if (sp == 0) break;
        if (!read_child_str(badge, sp, argv_bufs[argc], 64)) {
            return -BURMALDA_EFAULT;
        }
        argv_ptrs[argc] = argv_bufs[argc];
    }
    argv_ptrs[argc] = NULL;
    if (argc == 0) {
        argv_bufs[0][0] = '\0';
        argv_ptrs[0] = argv_bufs[0];
        argv_ptrs[1] = NULL;
    }

    if (_exec == NULL) return -BURMALDA_ENOSYS;
    long rc = _exec(_exec_ctx, badge, (seL4_Word)f->data, rfile_len(f), argv_ptrs);
    if (rc != 0) return -BURMALDA_ENOEXEC;

    bproc_reset(badge);
    return BURMALDA_NO_REPLY;
}

static long burmalda_handle_wait4(seL4_Word badge)
{
    long pid = burmalda_get_arg0();
    seL4_Word wstatus = (seL4_Word)burmalda_get_arg1();
    long options = burmalda_get_arg2();

    long status = 0;
    seL4_Word dead = 0;
    if (_dead_child != NULL) {
        dead = _dead_child(_dead_child_ctx, badge, &status);
        if (dead != 0 && (pid == -1 || pid == (long)dead) && _reap != NULL) {
            _reap(_reap_ctx, dead);
        }
    }
    if (dead != 0 && (pid == -1 || pid == (long)dead)) {
        uint32_t ws = (uint32_t)((status & 0xff) << 8);
        if (wstatus != 0) {
            burmalda_write_child(badge, wstatus, &ws, sizeof(ws));
        }
        return (long)dead;
    }
    if (dead != 0) return 0;

    if (options & 1) return 0;

    _pending_wait_valid = true;
    _pending_parent = badge;
    _pending_wstatus = wstatus;
    save_fault_mrs(_pending_mrs);
    return BURMALDA_NO_REPLY;
}

static long burmalda_handle_waitid(seL4_Word badge)
{
    seL4_Word sip = (seL4_Word)burmalda_get_arg2();

    long status = 0;
    seL4_Word dead = 0;
    if (_dead_child != NULL) {
        dead = _dead_child(_dead_child_ctx, badge, &status);
        if (dead != 0 && _reap != NULL) _reap(_reap_ctx, dead);
    }
    if (dead == 0 && sip != 0) {
        uint8_t zi[128];
        memset(zi, 0, sizeof(zi));
        uint32_t signo = 17;
        memcpy(zi + 0, &signo, 4);
        burmalda_write_child(badge, sip, zi, sizeof(zi));
        return 0;
    }
    if (sip != 0) {
        uint8_t zi[128];
        memset(zi, 0, sizeof(zi));
        uint32_t signo = 17, code = 1, pid = (uint32_t)dead, st = (uint32_t)status;
        memcpy(zi + 0, &signo, 4);
        memcpy(zi + 8, &code, 4);
        memcpy(zi + 16, &pid, 4);
        memcpy(zi + 24, &st, 4);
        if (!burmalda_write_child(badge, sip, zi, sizeof(zi))) {
            return -BURMALDA_EFAULT;
        }
    }
    return 0;
}

static long burmalda_handle_exit(seL4_Word badge)
{
    long status = burmalda_get_arg0();
    burmalda_putbuf("burmalda: pid ", 14);
    burmalda_put_dec((long)badge);
    burmalda_putbuf(" exited with status ", 20);
    burmalda_put_dec(status);
    burmalda_putbuf("\n", 1);

    seL4_Word parent = 0;
    if (_exit_fn != NULL) {
        parent = _exit_fn(_exit_ctx, badge, status);
    }

    if (parent != 0) {
        struct bproc *pbp = bproc_get(parent, true);
        if (pbp != NULL) {
            pbp->pending_mask |= (1UL << (17 - 1));
            pbp->sigchld_pid = badge;
            pbp->sigchld_status = (seL4_Word)status;
        }
    }

    if (_pending_wait_valid && parent != 0 && _pending_parent == parent) {
        uint32_t ws = (uint32_t)((status & 0xff) << 8);
        burmalda_write_child(parent, _pending_wstatus, &ws, sizeof(ws));
        seL4_Word ctx20[20];
        ctx_from_mrs(_pending_mrs, (seL4_Word)badge, ctx20);
        burmalda_write_child_ctx(parent, ctx20, true);
        _pending_wait_valid = false;
    }

    struct bproc *bp = bproc_get(badge, false);
    if (bp != NULL) bp->used = false;
    return BURMALDA_NO_REPLY;
}

static uint64_t burmalda_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static long burmalda_handle_clock_gettime(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg1();
    uint64_t ns;
    if (_tsc_hz == 0) {
        ns = burmalda_rdtsc();
    } else {
        uint64_t t = burmalda_rdtsc();
        uint64_t sec = t / _tsc_hz, rem = t % _tsc_hz;
        ns = sec * 1000000000ULL + (rem * 1000000000ULL) / _tsc_hz;
    }
    seL4_Word ts[2] = { (seL4_Word)(ns / 1000000000ULL),
                        (seL4_Word)(ns % 1000000000ULL) };
    if (!burmalda_write_child(badge, out, ts, sizeof(ts))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_uname(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg0();
    static const char fields[6][65] = {
        "Linux", "ferrix", "6.1.0-ferrix", "Ferrix", "", ""
    };
    if (!burmalda_write_child(badge, out, fields, sizeof(fields))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_getcwd(seL4_Word badge)
{
    seL4_Word buf = (seL4_Word)burmalda_get_arg0();
    long size = burmalda_get_arg1();
    if ((long)size < 2) return -BURMALDA_EINVAL;
    if (!burmalda_write_child(badge, buf, "/\0", 2)) return -BURMALDA_EFAULT;
    return 2;
}

static long burmalda_handle_getrlimit(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg1();
    seL4_Word lim[2] = { 8 * 1024 * 1024, ~(seL4_Word)0 };
    if (!burmalda_write_child(badge, out, lim, sizeof(lim))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_futex(seL4_Word badge)
{
    (void)badge;
    return 0;
}

static long burmalda_handle_ioctl(seL4_Word badge)
{
    long fd = burmalda_get_arg0();
    unsigned long cmd = (unsigned long)burmalda_get_arg1();
    seL4_Word argp = (seL4_Word)burmalda_get_arg2();

    bool tty = (fd >= 0 && fd <= 2);
    if (!tty) {
        struct bproc *bp = bproc_get(badge, false);
        tty = (bp != NULL && fd >= 3 && fd < BURMALDA_MAX_FDS &&
               bp->fds[fd].open && bp->fds[fd].f != NULL &&
               strcmp(bp->fds[fd].f->name, "/dev/console") == 0);
    }
    if (!tty) return -BURMALDA_ENOTTY;

    switch (cmd) {
    case 0x5401: {
        uint8_t t[60];
        memset(t, 0, sizeof(t));
        uint32_t iflag = 0x00000500, oflag = 0x00000003;
        uint32_t cflag = 0x000000b0, lflag = 0x0000008a;
        memcpy(t + 0, &iflag, 4);
        memcpy(t + 4, &oflag, 4);
        memcpy(t + 8, &cflag, 4);
        memcpy(t + 12, &lflag, 4);
        t[17 + 3] = 0x7f;
        if (!burmalda_write_child(badge, argp, t, sizeof(t))) {
            return -BURMALDA_EFAULT;
        }
        return 0;
    }
    case 0x5402: return 0;
    case 0x5413: {
        uint16_t ws[4] = { 25, 80, 0, 0 };
        if (!burmalda_write_child(badge, argp, ws, sizeof(ws))) {
            return -BURMALDA_EFAULT;
        }
        return 0;
    }
    default:
        return -BURMALDA_ENOTTY;
    }
}

static long burmalda_handle_fork(seL4_Word badge)
{
    if (_spawn == NULL) return -BURMALDA_ENOSYS;
    seL4_Word mrs[18];
    save_fault_mrs(mrs);
    seL4_Word child = _spawn(_spawn_ctx, badge);
    if (child == 0) return -BURMALDA_ENOMEM;

    struct bproc *cbp = bproc_get(child, true);
    struct bproc *pbp = bproc_get(badge, false);
    if (cbp != NULL && pbp != NULL) {
        cbp->ppid = badge;
        cbp->brk = pbp->brk;
    }

    seL4_Word ctx20[20];
    ctx_from_mrs(mrs, 0, ctx20);
    burmalda_write_child_ctx(child, ctx20, true);
    return (long)child;
}

static long burmalda_handle_exit(seL4_Word badge);

static long burmalda_handle_pselect6(seL4_Word badge)
{
    long nfds = burmalda_get_arg0();
    seL4_Word rdf = (seL4_Word)burmalda_get_arg1();
    seL4_Word wrf = (seL4_Word)burmalda_get_arg2();
    seL4_Word sigp = (seL4_Word)burmalda_get_arg5();

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    seL4_Word eff_mask = bp->blocked_mask;
    if (sigp != 0) {
        seL4_Word pr[2];
        if (burmalda_read_child(badge, pr, sigp, sizeof(pr)) && pr[0] != 0) {
            burmalda_read_child(badge, &eff_mask, pr[0], sizeof(eff_mask));
        }
    }
    if (burmalda_deliver_signal(bp, badge, eff_mask)) {
        return 0;
    }

    if (nfds <= 0 || nfds > 1024) return 0;
    seL4_Word bytes = ((seL4_Word)nfds + 7) / 8;

    uint8_t rset[128], wset[128];
    bool have_r = (rdf != 0) && burmalda_read_child(badge, rset, rdf, bytes);
    bool have_w = (wrf != 0) && burmalda_read_child(badge, wset, wrf, bytes);
    if (!have_r && !have_w) return 0;

    int ready = 0;
    for (int fd = 0; fd < nfds; fd++) {
        if (fd < 3 || fd >= BURMALDA_MAX_FDS || !bp->fds[fd].open) continue;
        if (bp->fds[fd].kind == FD_PIPE_RD) {
            if (have_r && (rset[fd / 8] & (1 << (fd % 8))) &&
                (bp->fds[fd].pipe->len > 0 || bp->fds[fd].pipe->wr_closed)) {
                ready++;
            }
        } else if (bp->fds[fd].kind == FD_PIPE_WR) {
            if (have_w && (wset[fd / 8] & (1 << (fd % 8))) &&
                bp->fds[fd].pipe->len < 4096) {
                ready++;
            }
        }
    }
    if (ready > 0) {
        if (have_r) {
            for (int fd = 0; fd < nfds; fd++) {
                bool ok = fd >= 3 && fd < BURMALDA_MAX_FDS && bp->fds[fd].open
                          && bp->fds[fd].kind == FD_PIPE_RD
                          && (bp->fds[fd].pipe->len > 0 || bp->fds[fd].pipe->wr_closed);
                if (!ok) rset[fd / 8] &= (uint8_t)~(1 << (fd % 8));
            }
            burmalda_write_child(badge, rdf, rset, bytes);
        }
        if (have_w) {
            for (int fd = 0; fd < nfds; fd++) {
                bool ok = fd >= 3 && fd < BURMALDA_MAX_FDS && bp->fds[fd].open
                          && bp->fds[fd].kind == FD_PIPE_WR
                          && bp->fds[fd].pipe->len < 4096;
                if (!ok) wset[fd / 8] &= (uint8_t)~(1 << (fd % 8));
            }
            burmalda_write_child(badge, wrf, wset, bytes);
        }
    }
    return ready;
}

static long burmalda_handle_poll(seL4_Word badge)
{
    seL4_Word fds_p = (seL4_Word)burmalda_get_arg0();
    long nfds = burmalda_get_arg1();

    if (nfds <= 0 || nfds > 64) return 0;
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL) return 0;

    uint8_t raw[64 * 8];
    if (!burmalda_read_child(badge, raw, fds_p, (seL4_Word)nfds * 8)) {
        return -BURMALDA_EFAULT;
    }
    int ready = 0;
    for (long i = 0; i < nfds; i++) {
        int32_t fd;
        uint16_t ev;
        memcpy(&fd, raw + i * 8, 4);
        memcpy(&ev, raw + i * 8 + 4, 2);
        uint16_t rev = 0;
        if (fd >= 0 && fd < BURMALDA_MAX_FDS && bp->fds[fd].open) {
            if (bp->fds[fd].kind == FD_PIPE_RD && (ev & 1)) {
                if (bp->fds[fd].pipe->len > 0 || bp->fds[fd].pipe->wr_closed) {
                    rev |= 1;
                }
            } else if (bp->fds[fd].kind == FD_PIPE_WR && (ev & 4)) {
                if (bp->fds[fd].pipe->len < 4096) rev |= 4;
            }
        }
        if (rev) ready++;
        memcpy(raw + i * 8 + 6, &rev, 2);
    }
    if (!burmalda_write_child(badge, fds_p, raw, (seL4_Word)nfds * 8)) {
        return -BURMALDA_EFAULT;
    }
    return ready;
}

static long burmalda_handle_stat(seL4_Word badge)
{
    seL4_Word pathp = (seL4_Word)burmalda_get_arg0();
    seL4_Word statp = (seL4_Word)burmalda_get_arg1();
    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) {
        return -BURMALDA_EFAULT;
    }
    struct rfile *f = ramfs_find(path);
    if (f == NULL) return -BURMALDA_ENOENT;
    uint8_t st[144];
    fill_stat(f, st);
    if (!burmalda_write_child(badge, statp, st, sizeof(st))) {
        return -BURMALDA_EFAULT;
    }
    return 0;
}

static long burmalda_handle_statx(seL4_Word badge);

static long burmalda_handle_sendfile(seL4_Word badge)
{
    long out_fd = burmalda_get_arg0();
    long in_fd  = burmalda_get_arg1();
    seL4_Word offp = (seL4_Word)burmalda_get_arg2();
    seL4_Word count = (seL4_Word)burmalda_get_arg3();

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    uint8_t kbuf[512];
    long total = 0;
    seL4_Word left = count;
    while (left > 0) {
        seL4_Word chunk = (left > sizeof(kbuf)) ? sizeof(kbuf) : left;
        long r = fd_read_buffered(badge, bp, in_fd, kbuf, chunk);
        if (r < 0) return (total > 0) ? total : -BURMALDA_EINVAL;
        if (r == 0) break;
        long w = fd_write_buffered(badge, bp, out_fd, kbuf, (seL4_Word)r);
        if (w < 0) return (total > 0) ? total : -BURMALDA_EINVAL;
        total += w;
        left -= (seL4_Word)w;
        if (offp != 0) {
            seL4_Word noff = 0;
            burmalda_read_child(badge, &noff, offp, sizeof(noff));
            noff += (seL4_Word)w;
            burmalda_write_child(badge, offp, &noff, sizeof(noff));
        }
    }
    return total;
}

static long burmalda_handle_copy_file_range(seL4_Word badge)
{
    long in_fd  = burmalda_get_arg0();
    seL4_Word off_in = (seL4_Word)burmalda_get_arg1();
    long out_fd = burmalda_get_arg2();
    seL4_Word off_out = (seL4_Word)burmalda_get_arg3();
    seL4_Word len = (seL4_Word)burmalda_get_arg4();

    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    uint8_t kbuf[512];
    long total = 0;
    seL4_Word left = len;
    while (left > 0) {
        seL4_Word chunk = (left > sizeof(kbuf)) ? sizeof(kbuf) : left;
        long r = fd_read_buffered(badge, bp, in_fd, kbuf, chunk);
        if (r <= 0) break;
        long w = fd_write_buffered(badge, bp, out_fd, kbuf, (seL4_Word)r);
        if (w < 0) break;
        total += w;
        left -= (seL4_Word)w;
        if (off_in != 0) {
            seL4_Word noff = 0;
            burmalda_read_child(badge, &noff, off_in, sizeof(noff));
            noff += (seL4_Word)w;
            burmalda_write_child(badge, off_in, &noff, sizeof(noff));
        }
        if (off_out != 0) {
            seL4_Word noff = 0;
            burmalda_read_child(badge, &noff, off_out, sizeof(noff));
            noff += (seL4_Word)w;
            burmalda_write_child(badge, off_out, &noff, sizeof(noff));
        }
    }
    return total;
}

static bool sig_is_fatal(int signo)
{
    switch (signo) {
    case 1: case 2: case 3: case 9: case 13: case 14:
    case 15: case 10: case 12: case 23: case 24: case 25:
    case 6: case 7: case 8: case 11: case 31:
        return true;
    default:
        return false;
    }
}

static void burmalda_raise_signal(seL4_Word target, int signo,
                                  seL4_Word from_pid)
{
    if (signo < 1 || signo > 64) return;
    if (target == 0) return;
    struct bproc *tp = bproc_get(target, true);
    if (tp == NULL) return;

    bool caught = tp->sigs[signo].handler > 1;
    if (sig_is_fatal(signo) && !caught && _terminate != NULL) {
        burmalda_putbuf("burmalda: kill pid ", 16);
        burmalda_put_dec((long)target);
        burmalda_putbuf(" sig ", 5);
        burmalda_put_dec(signo);
        burmalda_putbuf("\n", 1);
        _terminate(_terminate_ctx, target, signo);

        seL4_Word parent = 0;
        if (_exit_fn != NULL) {
            parent = _exit_fn(_exit_ctx, target, signo);
        }
        if (parent != 0) {
            struct bproc *pbp = bproc_get(parent, true);
            if (pbp != NULL) {
                pbp->pending_mask |= (1UL << (17 - 1));
                pbp->sigchld_pid = target;
                pbp->sigchld_status = (seL4_Word)signo;
            }
        }
        if (_pending_wait_valid && parent != 0 && _pending_parent == parent) {
            uint32_t ws = (uint32_t)(signo & 0x7f);
            burmalda_write_child(parent, _pending_wstatus, &ws, sizeof(ws));
            seL4_Word ctx20[20];
            ctx_from_mrs(_pending_mrs, (seL4_Word)target, ctx20);
            burmalda_write_child_ctx(parent, ctx20, true);
            _pending_wait_valid = false;
        }
        struct bproc *xbp = bproc_get(target, false);
        if (xbp != NULL) xbp->used = false;
        return;
    }

    tp->pending_mask |= (1UL << (signo - 1));
    tp->sigchld_pid = from_pid;
    tp->sigchld_status = 0;
}

/* -----------------------------------------------------------------------
 * Simple stub handlers
 * ----------------------------------------------------------------------- */

static long burmalda_handle_mprotect(void)    { return 0; }
static long burmalda_handle_madvise(void)     { return 0; }
static long burmalda_handle_fchdir(void)      { return 0; }
static long burmalda_handle_dup3(void)        { return 0; }
static long burmalda_handle_sigsuspend(void)  { return 0; }

static long burmalda_handle_tkill(seL4_Word badge)
{
    seL4_Word tid = (seL4_Word)burmalda_get_arg0();
    long sig = burmalda_get_arg1();
    burmalda_raise_signal(tid, (int)sig, badge);
    return 0;
}

static long burmalda_handle_tgkill(seL4_Word badge)
{
    seL4_Word tid = (seL4_Word)burmalda_get_arg1();
    long sig = burmalda_get_arg2();
    burmalda_raise_signal(tid, (int)sig, badge);
    return 0;
}

static long burmalda_handle_kill(seL4_Word badge)
{
    long pid = burmalda_get_arg0();
    long sig = burmalda_get_arg1();
    if (pid == -1 || pid == 0) return 0;
    if (pid < 0) return 0;
    burmalda_raise_signal((seL4_Word)pid, (int)sig, badge);
    return 0;
}

static long burmalda_handle_socket(void)      { return 3; }
static long burmalda_handle_accept(void)      { return -BURMALDA_EAGAIN; }
static long burmalda_handle_bind(void)        { return 0; }
static long burmalda_handle_listen(void)      { return 0; }
static long burmalda_handle_noop(void)        { return 0; }
static long burmalda_handle_umask(void)       { return 0x2; }
static long burmalda_handle_getuid(void)      { return 0; }
static long burmalda_handle_geteuid(void)     { return 0; }
static long burmalda_handle_getgid(void)      { return 0; }
static long burmalda_handle_getegid(void)     { return 0; }
static long burmalda_handle_getpid(seL4_Word badge)  { return (long)badge; }
static long burmalda_handle_getppid(seL4_Word badge)
{
    struct bproc *bp = bproc_get(badge, false);
    return (bp != NULL) ? (long)bp->ppid : 0;
}
static long burmalda_handle_getpgid(seL4_Word badge)
{
    long pid = burmalda_get_arg0();
    /* setpgid() is a no-op here: every process is its own group leader. */
    if (pid == 0) return (long)badge;
    if (pid < 0) return -BURMALDA_EINVAL;
    return pid;
}
static long burmalda_handle_set_tid_address(void) { return 1; }

static long burmalda_handle_timer_create(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg2();
    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;
    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!bp->timers[i].used) { slot = i; break; }
    }
    if (slot < 0) return -BURMALDA_ENOMEM;
    long id = slot + 1;
    bp->timers[slot].used = true;
    bp->timers[slot].armed = false;
    bp->timers[slot].signo = 14;
    if (out != 0) {
        if (!burmalda_write_child(badge, out, &id, sizeof(id))) {
            return -BURMALDA_EFAULT;
        }
    }
    return 0;
}

static long burmalda_handle_timer_settime(seL4_Word badge)
{
    long id = burmalda_get_arg0();
    long flags = burmalda_get_arg1();
    seL4_Word newp = (seL4_Word)burmalda_get_arg2();
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || id < 1 || id > 4 || !bp->timers[id - 1].used) {
        return -BURMALDA_EINVAL;
    }
    uint64_t spec[4];
    if (!burmalda_read_child(badge, spec, newp, sizeof(spec))) {
        return -BURMALDA_EFAULT;
    }
    uint64_t sec = spec[2], nsec = spec[3];
    struct btimer *t = &bp->timers[id - 1];
    if (sec == 0 && nsec == 0) { t->armed = false; return 0; }
    uint64_t rel_ns;
    if (flags & 1) {
        uint64_t now_ns = 0;
        uint64_t t_ = burmalda_rdtsc();
        if (_tsc_hz == 0) now_ns = t_;
        else {
            uint64_t sec2 = t_ / _tsc_hz, rem2 = t_ % _tsc_hz;
            now_ns = sec2 * 1000000000ULL + (rem2 * 1000000000ULL) / _tsc_hz;
        }
        rel_ns = (sec * 1000000000ULL + nsec) - now_ns;
    } else {
        rel_ns = sec * 1000000000ULL + nsec;
    }
    if (_tsc_hz == 0) t->deadline = burmalda_rdtsc() + rel_ns;
    else t->deadline = burmalda_rdtsc() + (rel_ns * _tsc_hz) / 1000000000ULL;
    t->armed = true;
    return 0;
}

static long burmalda_handle_timer_delete(seL4_Word badge)
{
    long id = burmalda_get_arg0();
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || id < 1 || id > 4) return -BURMALDA_EINVAL;
    bp->timers[id - 1].used = false;
    bp->timers[id - 1].armed = false;
    return 0;
}







static long burmalda_handle_arch_prctl(seL4_Word badge)
{
    long code = burmalda_get_arg0();
    seL4_Word addr = (seL4_Word)burmalda_get_arg1();
    if (code == BURMALDA_ARCH_SET_FS && _set_fs_base != NULL) {
        return _set_fs_base(_set_fs_base_ctx, badge, addr);
    }
    return -BURMALDA_ENOSYS;
}

static long burmalda_handle_sigreturn(seL4_Word badge)
{
    struct bproc *bp = bproc_get(badge, false);
    if (bp == NULL || !bp->in_signal) return 0;
    for (int i = 0; i < 18; i++) seL4_SetMR(i, bp->saved_mrs[i]);
    seL4_SetMR(seL4_UnknownSyscall_RAX, (seL4_Word)bp->saved_rax);
    bp->in_signal = false;
    _reply_raw = true;
    return 0;
}

static long burmalda_handle_nanosleep(seL4_Word badge)
{
    seL4_Word reqp = (seL4_Word)burmalda_get_arg1();

    uint64_t spec[2] = { 0, 0 };
    if (reqp != 0) {
        if (!burmalda_read_child(badge, spec, reqp, sizeof(spec))) {
            return -BURMALDA_EFAULT;
        }
    }
    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;

    uint64_t ns = spec[0] * 1000000000ULL + spec[1];
    uint64_t rel_ticks = (_tsc_hz == 0) ? ns : (ns * _tsc_hz) / 1000000000ULL;

    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!bp->timers[i].used) { slot = i; break; }
    }
    if (slot < 0) return -BURMALDA_ENOMEM;

    bp->timers[slot].used = true;
    bp->timers[slot].signo = 0;
    bp->timers[slot].deadline = burmalda_rdtsc() + rel_ticks;
    bp->timers[slot].armed = true;

    _sleep_proc = bp;
    save_fault_mrs(_sleep_mrs);
    _sleep_active = true;
    return BURMALDA_NO_REPLY;
}

static long burmalda_handle_setitimer(seL4_Word badge)
{
    seL4_Word newp = (seL4_Word)burmalda_get_arg1();
    struct bproc *bp = bproc_get(badge, true);
    if (bp == NULL) return -BURMALDA_ENOMEM;
    if (newp == 0) return 0;
    uint64_t spec[4] = { 0, 0, 0, 0 };
    burmalda_read_child(badge, spec, newp, sizeof(spec));
    uint64_t ns = spec[2] * 1000000000ULL + spec[3];
    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!bp->timers[i].used) { slot = i; break; }
    }
    if (slot < 0) return -BURMALDA_ENOMEM;
    bp->timers[slot].used = true;
    bp->timers[slot].signo = 14;
    bp->timers[slot].deadline = burmalda_rdtsc() +
        ((_tsc_hz == 0) ? ns : (ns * _tsc_hz) / 1000000000ULL);
    bp->timers[slot].armed = true;
    return 0;
}

/* SYS_prlimit64(pid, res, new*, old*) — report sane limits (8 MB stack,
 * 64 fds, unlimited core), accept sets. */
static long burmalda_handle_prlimit64(seL4_Word badge)
{
    seL4_Word newp = (seL4_Word)burmalda_get_arg2();
    seL4_Word oldp = (seL4_Word)burmalda_get_arg3();

    if (oldp != 0) {
        uint64_t rl[2] = { 0, 0 };
        long res = burmalda_get_arg1();
        switch (res) {
        case 7:  rl[0] = 64; rl[1] = 64; break;            /* RLIMIT_NOFILE */
        case 3:  rl[0] = 8*1024*1024; rl[1] = ~(seL4_Word)0; break; /* STACK */
        default: rl[0] = ~(seL4_Word)0; rl[1] = ~(seL4_Word)0; break;
        }
        if (!burmalda_write_child(badge, oldp, rl, sizeof(rl))) {
            return -BURMALDA_EFAULT;
        }
    }
    (void)newp;
    return 0;
}

static long burmalda_handle_flock(seL4_Word badge)
{
    (void)badge;
    return 0;
}

static long burmalda_handle_getrusage(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg1();
    uint8_t ru[144];
    memset(ru, 0, sizeof(ru));
    if (!burmalda_write_child(badge, out, ru, sizeof(ru))) return -BURMALDA_EFAULT;
    return 0;
}

static long burmalda_handle_times(seL4_Word badge)
{
    seL4_Word out = (seL4_Word)burmalda_get_arg0();
    if (out != 0) {
        uint64_t t[4];
        memset(t, 0, sizeof(t));
        uint64_t ns;
        uint64_t tt = burmalda_rdtsc();
        if (_tsc_hz == 0) ns = tt;
        else {
            uint64_t sec = tt / _tsc_hz, rem = tt % _tsc_hz;
            ns = sec * 1000000000ULL + (rem * 1000000000ULL) / _tsc_hz;
        }
        t[0] = ns / 10000000ULL;
        if (!burmalda_write_child(badge, out, t, sizeof(t))) return -BURMALDA_EFAULT;
    }
    uint64_t ns;
    uint64_t tt = burmalda_rdtsc();
    if (_tsc_hz == 0) ns = tt;
    else {
        uint64_t sec = tt / _tsc_hz, rem = tt % _tsc_hz;
        ns = sec * 1000000000ULL + (rem * 1000000000ULL) / _tsc_hz;
    }
    return (long)(ns / 10000000ULL);
}

static long burmalda_handle_sigaltstack(seL4_Word badge)
{
    seL4_Word oldp = (seL4_Word)burmalda_get_arg2();
    if (oldp != 0) {
        uint8_t z[24];
        memset(z, 0, sizeof(z));
        if (!burmalda_write_child(badge, oldp, z, sizeof(z))) return -BURMALDA_EFAULT;
    }
    return 0;
}


static long burmalda_handle_readlink(seL4_Word badge)
{
    seL4_Word pathp = (seL4_Word)burmalda_get_arg0();
    seL4_Word bufp = (seL4_Word)burmalda_get_arg1();
    long size = burmalda_get_arg2();
    char path[128];
    if (!read_child_str(badge, pathp, path, sizeof(path))) return -BURMALDA_EFAULT;
    const char *tgt = NULL;
    if (strcmp(path, "/proc/self/exe") == 0) tgt = "/bin/busybox";
    if (tgt == NULL) return -BURMALDA_ENOENT;
    seL4_Word n = strlen(tgt);
    if ((seL4_Word)size < n) n = (seL4_Word)size;
    if (!burmalda_write_child(badge, bufp, tgt, n)) return -BURMALDA_EFAULT;
    return (long)n;
}

static long burmalda_handle_pselect6(seL4_Word badge);

static long burmalda_handle_poll(seL4_Word badge);

static long burmalda_handle_stat(seL4_Word badge);

static long burmalda_handle_statx(seL4_Word badge);

static long burmalda_handle_sendfile(seL4_Word badge);

static long burmalda_handle_copy_file_range(seL4_Word badge);

/* -----------------------------------------------------------------------
 * Dispatch
 * ----------------------------------------------------------------------- */

static long burmalda_dispatch(seL4_Word badge, long nr)
{
    switch (nr) {
    case BURMALDA_SYS_read:             return burmalda_handle_read(badge);
    case BURMALDA_SYS_write:            return burmalda_handle_write(badge);
    case BURMALDA_SYS_open:             return burmalda_handle_openat(badge, false);
    case BURMALDA_SYS_close:            return burmalda_handle_close(badge);
    case BURMALDA_SYS_stat:             return burmalda_handle_stat(badge);
    case BURMALDA_SYS_fstat:            return burmalda_handle_fstat(badge);
    case BURMALDA_SYS_lseek:            return burmalda_handle_lseek(badge);
    case BURMALDA_SYS_mmap:             return burmalda_handle_mmap(badge);
    case BURMALDA_SYS_mprotect:         return burmalda_handle_mprotect();
    case BURMALDA_SYS_munmap:           return 0;
    case BURMALDA_SYS_brk:              return burmalda_handle_brk(badge);
    case BURMALDA_SYS_rt_sigaction:     return burmalda_handle_sigaction(badge);
    case BURMALDA_SYS_rt_sigprocmask:   return burmalda_handle_sigprocmask(badge);
    case BURMALDA_SYS_ioctl:            return burmalda_handle_ioctl(badge);
    case BURMALDA_SYS_writev:           return burmalda_handle_writev(badge);
    case BURMALDA_SYS_access:           return -BURMALDA_ENOENT;
    case BURMALDA_SYS_pipe:             return burmalda_handle_pipe2(badge);
    case BURMALDA_SYS_pipe2:            return burmalda_handle_pipe2(badge);
    case BURMALDA_SYS_dup2:             return burmalda_handle_dup2(badge);
    case BURMALDA_SYS_dup3:             return burmalda_handle_dup3();
    case BURMALDA_SYS_getdents64:       return burmalda_handle_getdents64(badge);
    case BURMALDA_SYS_connect:          return -BURMALDA_ECONNREFUSED;
    case BURMALDA_SYS_accept:           return burmalda_handle_accept();
    case BURMALDA_SYS_bind:             return burmalda_handle_bind();
    case BURMALDA_SYS_listen:           return burmalda_handle_listen();
    case BURMALDA_SYS_socket:           return burmalda_handle_socket();
    case BURMALDA_SYS_clone:            return burmalda_handle_fork(badge);
    case BURMALDA_SYS_fork:             return burmalda_handle_fork(badge);
    case BURMALDA_SYS_execve:           return burmalda_handle_execve(badge);
    case BURMALDA_SYS_exit:             /* fall through */
    case BURMALDA_SYS_exit_group:       return burmalda_handle_exit(badge);
    case BURMALDA_SYS_wait4:            return burmalda_handle_wait4(badge);
    case BURMALDA_SYS_waitid:           return burmalda_handle_waitid(badge);
    case BURMALDA_SYS_kill:             return burmalda_handle_kill(badge);
    case BURMALDA_SYS_uname:            return burmalda_handle_uname(badge);
    case BURMALDA_SYS_fcntl:            return burmalda_handle_fcntl();
    case BURMALDA_SYS_getcwd:           return burmalda_handle_getcwd(badge);
    case BURMALDA_SYS_chdir:            return burmalda_handle_fchdir();
    case BURMALDA_SYS_unlink:           return burmalda_handle_unlink(badge);
    case BURMALDA_SYS_chmod:            return burmalda_handle_noop();
    case BURMALDA_SYS_fchmod:           return burmalda_handle_noop();
    case BURMALDA_SYS_umask:            return burmalda_handle_umask();
    case BURMALDA_SYS_getrlimit:        return burmalda_handle_getrlimit(badge);
    case BURMALDA_SYS_getuid:           return burmalda_handle_getuid();
    case BURMALDA_SYS_geteuid:          return burmalda_handle_geteuid();
    case BURMALDA_SYS_getpid:           return burmalda_handle_getpid(badge);
    case BURMALDA_SYS_getgid:           return burmalda_handle_getgid();
    case BURMALDA_SYS_getegid:          return burmalda_handle_getegid();
    case BURMALDA_SYS_getppid:          return burmalda_handle_getppid(badge);
    case BURMALDA_SYS_getpgid:          return burmalda_handle_getpgid(badge);
    case BURMALDA_SYS_setsid:           return burmalda_handle_noop();
    case BURMALDA_SYS_setpgid:          return burmalda_handle_noop();
    case BURMALDA_SYS_arch_prctl:       return burmalda_handle_arch_prctl(badge);
    case BURMALDA_SYS_tkill:            return burmalda_handle_tkill(badge);
    case BURMALDA_SYS_futex:            return burmalda_handle_futex(badge);
    case BURMALDA_SYS_tgkill:           return burmalda_handle_tgkill(badge);
    case BURMALDA_SYS_set_tid_address:  return burmalda_handle_set_tid_address();
    case BURMALDA_SYS_timer_create:     return burmalda_handle_timer_create(badge);
    case BURMALDA_SYS_timer_settime:    return burmalda_handle_timer_settime(badge);
    case BURMALDA_SYS_timer_delete:     return burmalda_handle_timer_delete(badge);
    case BURMALDA_SYS_clock_gettime:    return burmalda_handle_clock_gettime(badge);
    case BURMALDA_SYS_openat:           return burmalda_handle_openat(badge, true);
    case BURMALDA_SYS_poll:             return burmalda_handle_poll(badge);
    case BURMALDA_SYS_pselect6:         return burmalda_handle_pselect6(badge);
    case BURMALDA_SYS_statx:            return burmalda_handle_statx(badge);
    case BURMALDA_SYS_sendfile:         return burmalda_handle_sendfile(badge);
    case BURMALDA_SYS_copy_file_range:  return burmalda_handle_copy_file_range(badge);
    case BURMALDA_SYS_rt_sigreturn:     return burmalda_handle_sigreturn(badge);
    case BURMALDA_SYS_nanosleep:        return burmalda_handle_nanosleep(badge);
    case BURMALDA_SYS_clock_nanosleep:  return burmalda_handle_nanosleep(badge);
    case BURMALDA_SYS_setitimer:        return burmalda_handle_setitimer(badge);
    case BURMALDA_SYS_getrusage:        return burmalda_handle_getrusage(badge);
    case BURMALDA_SYS_times:            return burmalda_handle_times(badge);
    case BURMALDA_SYS_sigaltstack:      return burmalda_handle_sigaltstack(badge);
    case BURMALDA_SYS_rt_sigsuspend:    return burmalda_handle_sigsuspend();
    case BURMALDA_SYS_madvise:          return burmalda_handle_madvise();
    case BURMALDA_SYS_fchdir:           return burmalda_handle_fchdir();
    case BURMALDA_SYS_readlink:         return burmalda_handle_readlink(badge);
    case BURMALDA_SYS_prlimit64:        return burmalda_handle_prlimit64(badge);
    case BURMALDA_SYS_flock:            return burmalda_handle_flock(badge);
    case BURMALDA_SYS_setrlimit:        return burmalda_handle_noop();
    case BURMALDA_SYS_reboot:           return burmalda_handle_noop();
    case BURMALDA_SYS_prctl:            return burmalda_handle_noop();
    case BURMALDA_SYS_gettid:           return burmalda_handle_getpid(badge);
    default:
        burmalda_putbuf("burmalda: unhandled syscall nr=", 31);
        burmalda_put_dec(nr);
        burmalda_putbuf(" a0=", 4);
        burmalda_put_hex((seL4_Word)burmalda_get_arg0());
        burmalda_putbuf(" a1=", 4);
        burmalda_put_hex((seL4_Word)burmalda_get_arg1());
        burmalda_putbuf(" a2=", 4);
        burmalda_put_hex((seL4_Word)burmalda_get_arg2());
        burmalda_putbuf(" — ENOSYS\n", 10);
        return -BURMALDA_ENOSYS;
    }
}

/* -----------------------------------------------------------------------
 * Main dispatch loop
 * ----------------------------------------------------------------------- */

#ifdef CONFIG_KERNEL_MCS

void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj)
{
    ramfs_init();
    seL4_Word badge = 0;
    seL4_MessageInfo_t info = seL4_Recv(ep, &badge, reply_obj);

    for (;;) {
        for (int i = 0; i < 18; i++) _fault_mrs[i] = seL4_GetMR(i);
        _reply_raw = false;
        _mrs_modified = false;

        if (badge == 0) {
            seL4_IRQHandler_Ack(_serial_irq_notif);
            burmalda_complete_deferred_read();
            burmalda_complete_sleeps();
            info = seL4_ReplyRecv(ep, seL4_MessageInfo_new(0, 0, 0, 0),
                                  &badge, reply_obj);
            continue;
        }

        if (seL4_MessageInfo_get_label(info) != seL4_Fault_UnknownSyscall) {
            burmalda_report_unexpected_fault(info);
            info = seL4_ReplyRecv(ep, seL4_MessageInfo_new(0, 0, 0, 0),
                                  &badge, reply_obj);
            continue;
        }

        burmalda_timer_check(bproc_get(badge, false));
        burmalda_complete_deferred_read();
        burmalda_complete_sleeps();
        long nr = burmalda_get_syscall_nr();
        long retval = burmalda_dispatch(badge, nr);

        if (retval == BURMALDA_NO_REPLY) {
            info = seL4_Recv(ep, &badge, reply_obj);
        } else {
            if (!_mrs_modified) {
                for (int i = 0; i < 18; i++) seL4_SetMR(i, _fault_mrs[i]);
            }
            if (_reply_raw) {
                _reply_raw = false;
                info = seL4_ReplyRecv(ep,
                                      seL4_MessageInfo_new(0, 0, 0,
                                                           seL4_UnknownSyscall_Syscall),
                                      &badge, reply_obj);
            } else {
                info = seL4_ReplyRecv(ep, burmalda_make_reply(retval),
                                      &badge, reply_obj);
            }
        }
    }
}

#else /* non-MCS */

void burmalda_run(seL4_CPtr ep, seL4_CPtr reply_obj)
{
    (void)reply_obj;
    ramfs_init();

    for (;;) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(ep, &badge);

        for (int i = 0; i < 18; i++) _fault_mrs[i] = seL4_GetMR(i);
        _reply_raw = false;
        _mrs_modified = false;

        if (badge == 0) {
            seL4_IRQHandler_Ack(_serial_irq_notif);
            burmalda_complete_deferred_read();
            burmalda_complete_sleeps();
            continue;
        }

        if (seL4_MessageInfo_get_label(info) != seL4_Fault_UnknownSyscall) {
            burmalda_report_unexpected_fault(info);
            continue;
        }

        burmalda_timer_check(bproc_get(badge, false));
        burmalda_complete_deferred_read();
        burmalda_complete_sleeps();
        long nr = burmalda_get_syscall_nr();
        long retval = burmalda_dispatch(badge, nr);

        if (retval != BURMALDA_NO_REPLY) {
            if (_reply_raw) {
                _reply_raw = false;
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0,
                                                seL4_UnknownSyscall_Syscall));
            } else {
                if (!_mrs_modified) {
                    for (int i = 0; i < 18; i++) {
                        seL4_SetMR(i, _fault_mrs[i]);
                    }
                }
                seL4_Reply(burmalda_make_reply(retval));
            }
        }
    }
}

#endif /* CONFIG_KERNEL_MCS */
