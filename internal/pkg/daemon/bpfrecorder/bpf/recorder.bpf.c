#include <vmlinux.h>

#include <linux/limits.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_CHILD_PIDS 1024
#define MAX_COMM_LEN 64

#define PROBE_TYPE_OPEN 0
#define PROBE_TYPE_EXEC 1
#define PROBE_TYPE_CLOSE 2
#define PROBE_TYPE_MMAP_EXEC 3
#define PROBE_TYPE_READ 4
#define PROBE_TYPE_WRITE 5
#define PROBE_TYPE_SOCKET 6
#define PROBE_TYPE_CAP 7
#define PROBE_TYPE_EXIT 8

#define PROT_READ 0x1  /* Page can be read.  */
#define PROT_WRITE 0x2 /* Page can be written.  */
#define PROT_EXEC 0x4  /* Page can be executed.  */
#define PROT_NONE 0x0

#define SOCK_RAW 3

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                 // mntns
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} mntns_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);    // PID
    __type(value, u32);  // mntns ID
} pid_mntns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CHILD_PIDS);
    __type(key, u32);
    __type(value, bool);
} child_pids SEC(".maps");

struct event_t {
    u32 pid;
    u32 mntns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} apparmor_events SEC(".maps");

typedef struct __attribute__((__packed__)) apparmor_event_data {
    u32 pid;
    u32 mntns;
    u8 type;
    u64 flags;
    u64 fd;
    char data[PATH_MAX];
} apparmor_event_data_t;

const volatile char filter_name[MAX_COMM_LEN] = {};

static inline bool has_filter();
static inline bool matches_filter(char * comm);

typedef struct saved_state {
    const char * filename;
    u64 flags;
} saved_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, saved_state_t);
} states_map SEC(".maps");

static __always_inline int save_args(const char * filename, u64 flags)
{
    u32 id = bpf_get_current_pid_tgid();

    saved_state_t state = {};
    state.filename = filename;
    state.flags = flags;

    bpf_map_update_elem(&states_map, &id, &state, BPF_ANY);

    return 0;
}

static __always_inline int load_args(const char ** filename, u64 * flags)
{
    u32 id = bpf_get_current_pid_tgid();

    saved_state_t * saved_state = bpf_map_lookup_elem(&states_map, &id);
    if (saved_state == 0)
        return -1;

    u64 local_flags;
    bpf_probe_read(filename, sizeof(filename), &saved_state->filename);
    bpf_probe_read(flags, sizeof(*flags), &saved_state->flags);

    bpf_map_delete_elem(&states_map, &id);

    return 0;
}

/**
 * get_mntns returns the mntns in case the call should be taken into account.
 * 0 is returned when the process should not be processed. The following
 * criteria are used:
 *   - host processes are excluded
 *   - child processes are included
 *   - program name if filtering on this is required
 */
static __always_inline u32 get_mntns()
{
    // Get the current mntns
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u32 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (mntns == 0) {
        return 0;
    }

    // Filter out mntns of the host PID to exclude host processes
    u32 hostPid = 1;
    u32 * host_mntns = NULL;
    host_mntns = bpf_map_lookup_elem(&pid_mntns, &hostPid);
    if (host_mntns != NULL && *host_mntns == mntns) {
        return 0;
    }

    // Filter per program name if requested
    if (has_filter()) {

        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bool is_child = bpf_map_lookup_elem(&child_pids, &pid) != NULL;
        char comm[MAX_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));

        if (!is_child && !matches_filter(comm)) {
            return 0;
        }
    }

    return mntns;
}

static __always_inline int enter_execve(
    unsigned long * pathname_ptr
) {
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_EXEC;

        const char * pathname;
        int res;
        res = bpf_probe_read(&pathname, sizeof(pathname), pathname_ptr);
        if (res != 0) {
            bpf_printk("failed to get pathname pointer\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        res = bpf_probe_read_str(&event->data, PATH_MAX, pathname);
        if (res > 0)
            event->data[(res - 1) & (PATH_MAX - 1)] = 0;
        bpf_printk("executed process (execve, pid %d): %s\n", pid, event->data);
        bpf_ringbuf_submit(event, 0);
        bool ok = true;
        bpf_map_update_elem(&child_pids, &pid, &ok, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int syscall__execve(struct trace_event_raw_sys_enter * ctx)
{
    return enter_execve(&ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int syscall__execveat(struct trace_event_raw_sys_enter * ctx)
{
    return enter_execve(&ctx->args[1]);
}

static __always_inline int enter_open(
    unsigned long * pathname_ptr,
    unsigned long * flags_ptr
) {
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    int res;
    const char * pathname;
    res = bpf_probe_read(&pathname, sizeof(pathname), pathname_ptr);
    if (res != 0) {
        bpf_printk("failed to get pathname pointer");
        return 0;
    }

    u64 flags;
    res = bpf_probe_read(&flags, sizeof(flags), flags_ptr);
    if (res != 0) {
        bpf_printk("failed to get flags value");
        return 0;
    }

    save_args(pathname, flags);
    return 0;
}

// A limitation with tracing open/openat is that symlinks will not be resolved.
// Using LSM hooks like security_open would solve this.
SEC("tracepoint/syscalls/sys_enter_open")
int syscall__open(struct trace_event_raw_sys_enter * ctx)
{
    return enter_open(&ctx->args[0], &ctx->args[1]);
}

// A limitation with tracing open/openat is that symlinks will not be resolved.
// Using LSM hooks like security_open would solve this.
SEC("tracepoint/syscalls/sys_enter_openat")
int syscall__openat(struct trace_event_raw_sys_enter * ctx)
{
    return enter_open(&ctx->args[1], &ctx->args[2]);
}

static __always_inline int exit_open(struct trace_event_raw_sys_exit * ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    const char * orig_filename;
    u64 flags;
    if (load_args(&orig_filename, &flags) != 0) {
        bpf_printk("failed to load saved args\n");
        return 0;
    }

    apparmor_event_data_t * event;
    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_OPEN;
        event->flags = flags;
        event->fd = 0;

        int res;
        res = bpf_probe_read(&event->fd, sizeof(event->fd), &ctx->ret);
        if (res != 0) {
            bpf_printk("failed to get fd value\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        const char * pathname;
        res = bpf_probe_read(&pathname, sizeof(pathname), &orig_filename);

        bpf_printk("loading ptr: %x, flags: %d\n", pathname, flags);

        if (res != 0) {
            bpf_printk("failed to get pathname pointer\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        res = bpf_probe_read_str(&event->data, sizeof(event->data), pathname);
        if (res > 0)
            event->data[(res - 1) & (PATH_MAX - 1)] = 0;
        bpf_printk("opening file: %s with mode: %lu\n", event->data, event->fd);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int syscall__exit_open(struct trace_event_raw_sys_exit * ctx)
{
    return exit_open(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int syscall__exit_openat(struct trace_event_raw_sys_exit * ctx)
{
    return exit_open(ctx);
}

SEC("tracepoint/syscalls/sys_enter_close")
int syscall__close(struct trace_event_raw_sys_enter * ctx)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_CLOSE;

        u64 fd;
        int res;
        res = bpf_probe_read(&fd, sizeof(fd), &ctx->args[0]);
        if (res != 0) {
            bpf_printk("failed to get closed fd\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        event->fd = fd;
        bpf_printk("closed fd: %d\n", fd);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int syscall__mmap(struct trace_event_raw_sys_enter * ctx)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    u64 prot;
    u64 fd;
    int res;

    res = bpf_probe_read(&fd, sizeof(fd), &ctx->args[4]);
    if (res != 0) {
        bpf_printk("failed to get mmap fd\n");
        return 0;
    }
    res = bpf_probe_read(&prot, sizeof(prot), &ctx->args[2]);
    if (res != 0) {
        bpf_printk("failed to get mmap prot\n");
        return 0;
    }
    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_MMAP_EXEC;
        event->fd = fd;
        event->flags = prot;

        bpf_printk("Mmaped fd: %d\n", fd);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__write(struct trace_event_raw_sys_enter * ctx)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_WRITE;

        u64 fd;
        int res;
        res = bpf_probe_read(&fd, sizeof(fd), &ctx->args[0]);
        if (res != 0) {
            bpf_printk("failed to get written to fd\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        event->fd = fd;
        bpf_printk("writing to fd: %d\n", fd);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int syscall__read(struct trace_event_raw_sys_enter * ctx)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_READ;

        u64 fd;
        int res;
        res = bpf_probe_read(&fd, sizeof(fd), &ctx->args[0]);
        if (res != 0) {
            bpf_printk("failed to get read from fd\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        event->fd = fd;
        bpf_printk("reading to fd: %d\n", fd);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int syscall__socket(struct trace_event_raw_sys_enter * ctx)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_SOCKET;

        u64 type;
        int res;
        res = bpf_probe_read(&type, sizeof(type), &ctx->args[1]);
        if (res != 0) {
            bpf_printk("failed to get socket type\n");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        event->flags = type;

        bpf_printk("requesting raw socket\n");
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    unsigned long cap = PT_REGS_PARM3(ctx);

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_CAP;

        event->flags = cap;

        bpf_printk("requesting capability: %i\n", cap);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

static __always_inline void handle_exit()
{
    apparmor_event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return;

    // only report when the main process exits.
    bool * is_child = bpf_map_lookup_elem(&child_pids, &pid);
    if (is_child != NULL) {
        return;
    }

    event =
        bpf_ringbuf_reserve(&apparmor_events, sizeof(apparmor_event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = PROBE_TYPE_EXIT;
        bpf_ringbuf_submit(event, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_exit")
int syscall__exit(struct trace_event_raw_sys_enter * ctx)
{
    handle_exit();
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int syscall__exit_group(struct trace_event_raw_sys_enter * ctx)
{
    handle_exit();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter * args)
{
    // Sanity check for syscall ID range
    u32 syscall_id = args->id;
    if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (mntns == 0) {
        return 0;
    }

    // Notify the userspace when a new PID is found. This will allow
    // the userspace to look up the container ID from cgroups of the
    // process. And using the container ID, it will search further the
    // security profile assigned to this container in the cluster.
    u32 * current_pid_mntns = NULL;
    current_pid_mntns = bpf_map_lookup_elem(&pid_mntns, &pid);
    if (current_pid_mntns == NULL) {
        struct event_t * event =
            bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (event) {
            bpf_printk("send event pid: %u, mntns: %u\n", pid, mntns);

            event->pid = pid;
            event->mntns = mntns;
            bpf_ringbuf_submit(event, 0);

            bpf_map_update_elem(&pid_mntns, &pid, &mntns, BPF_ANY);
        }
    }

    // Record the syscall for this mntns
    u8 * const mntns_syscall_value =
        bpf_map_lookup_elem(&mntns_syscalls, &mntns);
    if (mntns_syscall_value) {
        mntns_syscall_value[syscall_id] = 1;
    } else {
        // Initialise the syscalls recording buffer and record this syscall.
        static const char init[MAX_SYSCALLS];
        bpf_map_update_elem(&mntns_syscalls, &mntns, &init, BPF_ANY);
        u8 * const value = bpf_map_lookup_elem(&mntns_syscalls, &mntns);
        if (!value) {
            // Should not happen, we updated the element straight ahead
            bpf_printk(
                "look up item in mntns_syscalls map failed pid: %u, mntns: %u\n",
                pid, mntns);
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}


static inline bool has_filter()
{
    return filter_name[0] != 0;
}

static inline bool matches_filter(char * comm)
{
    // We cannot use __builtin_memcmp() until llvm bug
    // https://llvm.org/bugs/show_bug.cgi?id=26218 got resolved
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        if (comm[i] != filter_name[i]) {
            return false;
        }

        // Stop searching when comm is done
        if (comm[i] == 0) {
            break;
        }
    }

    return true;
}
