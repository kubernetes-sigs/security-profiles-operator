#include <vmlinux.h>

#include <linux/limits.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_CHILD_PIDS 1024

// We don't have TASK_COMM_LEN in userspace, so we define
// a static MAX_COMM_LEN which is supposed to be >= TASK_COMM_LEN
#define MAX_COMM_LEN 1024

#define EVENT_TYPE_NEWPID 0
#define EVENT_TYPE_EXIT 1
#define EVENT_TYPE_APPARMOR_FILE 2
#define EVENT_TYPE_APPARMOR_SOCKET 3
#define EVENT_TYPE_APPARMOR_CAP 4

#define FLAG_READ 0x1
#define FLAG_WRITE 0x2
#define FLAG_EXEC 0x4
#define FLAG_SPAWN 0x8

#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
#define FMODE_EXEC 0x20

#define PROT_READ 0x1  /* Page can be read.  */
#define PROT_WRITE 0x2 /* Page can be written.  */
#define PROT_EXEC 0x4  /* Page can be executed.  */
#define PROT_NONE 0x0

#define S_IFIFO 0010000
#define S_IFDIR 0040000

#define CAP_OPT_NOAUDIT 0b10

#define SOCK_RAW 3

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

// toggle this for additional debug output
#define trace_hook(...)
// #define trace_hook(...) bpf_printk(__VA_ARGS__)

// Keep track of all mount namespaces that should be (temporarily) excluded from
// recording. When running in Kubernetes, we generally ignore the host mntns.
// Additionally, we exclude individual containers during startup.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} exclude_mntns SEC(".maps");

// Track syscalls for each mtnns
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                 // mntns
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} mntns_syscalls SEC(".maps");

// Track active (known) PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, bool);
} active_pids SEC(".maps");

// Keep track of all child PIDs when observing
// a particular program name.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CHILD_PIDS);
    __type(key, u32);
    __type(value, bool);
} child_pids SEC(".maps");

// send events to userland
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

typedef struct __attribute__((__packed__)) event_data {
    u32 pid;
    u32 mntns;
    u8 type;
    u64 flags;
    char data[PATH_MAX];
} event_data_t;

const volatile char filter_name[MAX_COMM_LEN] = {};

static const bool TRUE = true;
static inline bool has_filter();
static inline bool matches_filter(char * comm);

/**
 * get_mntns returns the mntns in case the call should be taken into account.
 * 0 is returned when the process should not be processed. The following
 * criteria are used:
 *   - host processes are excluded (if system mntns is set)
 *   - child processes are included
 *   - program name if filter is active
 */
static __always_inline u32 get_mntns()
{
    // Get the current mntns
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u32 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (mntns == 0) {
        return 0;
    }

    // When running in a Kubernetes context:
    // Filter out mntns of the host PID to exclude host processes
    if (bpf_map_lookup_elem(&exclude_mntns, &mntns) != NULL) {
        return 0;
    }

    // Filter per program name if requested
    if (has_filter()) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bool is_child = bpf_map_lookup_elem(&child_pids, &pid) != NULL;
        char comm[TASK_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));

        if (!is_child && !matches_filter(comm)) {
            return 0;
        }
    }

    return mntns;
}

// Debug method to report access to a canary file.
// This is useful during development to see if a particular code path is hit
// and bpf_printk output is inaccessible.
static __always_inline void debug_add_canary_file(char * filename) {
    event_data_t * event = bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (!event) {
        bpf_printk("Failed to add canary file: %s", filename);
        return;
    }
    bpf_core_read_str(event->data, sizeof(event->data), filename);
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->mntns = get_mntns();
    event->type = EVENT_TYPE_APPARMOR_FILE;
    event->flags = FLAG_READ | FLAG_WRITE;
    bpf_ringbuf_submit(event, 0);
}

static u64 _file_event_inode;
static u64 _file_event_flags;
static u32 _file_event_pid;

static __always_inline int register_file_event(struct file * file, u64 flags)
{
    // ignore unix pipes
    if (file == NULL || file->f_inode->i_mode & S_IFIFO) {
        return 0;
    }

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    // discard repeated calls
    u64 inode = file->f_inode->i_ino;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool same_file = inode == _file_event_inode && pid == _file_event_pid;
    bool flags_are_subset = (flags | _file_event_flags) == _file_event_flags;
    if (same_file && flags_are_subset) {
        bpf_printk("register_file_event skipped");
        return 0;
    }

    event_data_t * event;
    event = bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (!event) {
        return 0;
    }

    int pathlen = bpf_d_path(&file->f_path, event->data, sizeof(event->data));
    if (pathlen < 0) {
        bpf_printk("register_file_event bpf_d_path failed: %i\n", pathlen);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    if (file->f_inode->i_mode & S_IFDIR) {
        // more checks than necessary, but only checking each offset
        // individually makes the ebpf verifier happy.
        if (pathlen >= 2 && pathlen - 2 < sizeof(event->data) &&
            pathlen - 1 < sizeof(event->data) &&
            pathlen < sizeof(event->data)) {
            if (event->data[pathlen - 2] != '/') {
                // No trailing slash, add `/` and move null byte.
                event->data[pathlen - 1] = '/';
                event->data[pathlen] = '\0';
            }
        } else {
            bpf_printk("failed to fixup directory entry, not enough space.");
        }
    }

    event->pid = pid;
    event->mntns = mntns;
    event->type = EVENT_TYPE_APPARMOR_FILE;
    event->flags = flags;

    // This debug log does not work on old kernels, see
    // https://github.com/libbpf/libbpf-bootstrap/issues/206#issuecomment-1694085235
    // bpf_printk(
    //    "register_file_event: %i, %s with flags=%d, mode=%d, inode_mode=%d\n",
    //    file, event->data, flags, file->f_mode, file->f_inode->i_mode);
    bpf_ringbuf_submit(event, 0);

    _file_event_inode = inode;
    _file_event_pid = pid;
    _file_event_flags = same_file ? (flags | _file_event_flags) : flags;

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file * file)
{
    // bpf_printk("file_open");
    u64 flags = 0;
    if (file->f_mode & FMODE_READ) {
        flags |= FLAG_READ;
    }
    if (file->f_mode & FMODE_WRITE) {
        flags |= FLAG_WRITE;
    }
    if (file->f_mode & FMODE_EXEC) {
        flags |= FLAG_EXEC;
    }
    return register_file_event(file, flags);
}

SEC("lsm/file_lock")
int BPF_PROG(file_lock, struct file * file)
{
    // bpf_printk("file_lock");
    return register_file_event(file, FLAG_WRITE);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file * file, unsigned long prot,
             unsigned long flags)
{
    // bpf_printk("mmap_file");
    u64 file_flags = 0;
    if (prot & PROT_READ) {
        file_flags |= FLAG_READ;
    }
    if (prot & PROT_WRITE) {
        file_flags |= FLAG_WRITE;
    }
    if (prot & PROT_EXEC) {
        file_flags |= FLAG_EXEC;
    }
    return register_file_event(file, file_flags);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm * bprm)
{
    // bpf_printk("bprm_check_security");
    return register_file_event(bprm->file, FLAG_SPAWN);
}

SEC("tracepoint/syscalls/sys_enter_socket")
int sys_enter_socket(struct trace_event_raw_sys_enter * ctx)
{
    event_data_t * event;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = EVENT_TYPE_APPARMOR_SOCKET;

        u64 type;
        int res;
        res = bpf_core_read(&type, sizeof(type), &ctx->args[1]);
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
int BPF_KPROBE(cap_capable)
{
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    unsigned long cap = PT_REGS_PARM3(ctx);
    unsigned long cap_opt = PT_REGS_PARM4(ctx);
    // bpf_printk("requesting capability: cap=%i cap_opt=%i\n", cap, cap_opt);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    // TODO: This should be implemented like the seccomp syscalls map.
    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->mntns = mntns;
        event->type = EVENT_TYPE_APPARMOR_CAP;

        event->flags = cap;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec * ctx)
{
    if (!has_filter()) {
        return 0;
    }

    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u32 parent_pid = BPF_CORE_READ(task, real_parent, pid);
    bool is_child = bpf_map_lookup_elem(&child_pids, &parent_pid) != NULL;

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    if (is_child || matches_filter(comm)) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        trace_hook("adding child pid: %u", pid);
        bpf_map_update_elem(&child_pids, &pid, &TRUE, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void * ctx)
{
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ok = bpf_map_delete_elem(&active_pids, &pid);
    if (ok != 0) {
        return 0;  // key not found
    }
    bpf_map_delete_elem(&child_pids, &pid);

    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->mntns = mntns;
        event->type = EVENT_TYPE_EXIT;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// Detect clone() from PIDs in child_pids and add the new PIDs to the map.
SEC("tracepoint/syscalls/sys_exit_clone")
int sys_exit_clone(struct trace_event_raw_sys_exit * ctx)
{
    u32 ret = ctx->ret;
    // We only need the fork, the existing process is already traced.
    if (ret == 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool is_child = bpf_map_lookup_elem(&child_pids, &pid) != NULL;
    if (is_child) {
        bpf_printk("adding child pid from clone: %u", ret);
        bpf_map_update_elem(&child_pids, &ret, &TRUE, BPF_ANY);
    }
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

    u32 mntns = get_mntns();
    if (mntns == 0) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Notify the userspace when a new PID is found. This will allow
    // the userspace to look up the container ID from cgroups of the
    // process. And using the container ID, it will search further the
    // security profile assigned to this container in the cluster.
    if (bpf_map_lookup_elem(&active_pids, &pid) == NULL) {
        event_data_t * event =
            bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
        if (event) {
            bpf_printk("send event pid: %u, mntns: %u\n", pid, mntns);

            event->type = EVENT_TYPE_NEWPID;
            event->pid = pid;
            event->mntns = mntns;

            bpf_ringbuf_submit(event, 0);

            bpf_map_update_elem(&active_pids, &pid, &TRUE, BPF_ANY);
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
                "look up item in mntns_syscalls map failed pid: %u, mntns: "
                "%u\n",
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
    // Use TASK_COMM_LEN - 1 because the last byte is a null byte due to
    // truncation and MAX_COMM_LEN is potentially longer.
    for (int i = 0; i < TASK_COMM_LEN - 1; i++) {
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
