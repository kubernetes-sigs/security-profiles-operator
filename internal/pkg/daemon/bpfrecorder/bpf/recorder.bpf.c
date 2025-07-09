#include <vmlinux.h>

#include <linux/limits.h>

#include "bpf_d_path_tetragon.h"
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
#define EVENT_TYPE_CLEAR_MNTNS 5

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

#define S_IFMT 0170000
#define S_IFIFO 0010000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFBLK 0060000
#define S_IFSOCK 0140000

#define CAP_OPT_NOAUDIT 0b10

#define PR_GET_PDEATHSIG 2

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
// #define trace_hook(...) if(get_mntns()) { bpf_printk(__VA_ARGS__) }

// are we currently recording?
// If yes, the only map element is set to true.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, bool);
} is_recording SEC(".maps");

static volatile bool _is_recording_cached = false;

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

static const char FORWARD_SLASH[] = "/";
static const char RUNC_INIT[] = "runc:[2:INIT]";
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

static __always_inline u32 clear_mntns_seccomp(u32 mntns)
{
    trace_hook("clear_mntns_seccomp mntns=%u", mntns);
    bpf_map_delete_elem(&mntns_syscalls, &mntns);
    return 0;
}

static __always_inline u32 clear_mntns_apparmor(u32 mntns)
{
    trace_hook("clear_mntns_apparmor mntns=%u", mntns);
    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->mntns = mntns;
        event->type = EVENT_TYPE_CLEAR_MNTNS;
        bpf_ringbuf_submit(event, 0);
        return 0;
    } else {
        return -1;
    }
}

static __always_inline bool is_runc_init()
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    for (int i = 0; i < sizeof(RUNC_INIT); i++) {
        if (comm[i] != RUNC_INIT[i])
            return false;
    }
    return true;
}

// Debug method to report access to a canary file.
// This is useful during development to see if a particular code path is hit
// and bpf_printk output is inaccessible.
static __always_inline void debug_add_canary_file(char * filename)
{
    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
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

// Create a struct path for a given dentry by combining it with the mount point
// of its parent path. Note that the returned path does not work with the
// kernel's bpf_d_path, as it does not like stack pointers.
static __always_inline struct path make_path(struct dentry * dentry,
                                             struct path * path)
{
    struct path ret = {
        .mnt = BPF_CORE_READ(path, mnt),
        .dentry = dentry,
    };
    return ret;
}

static __always_inline int bpf_d_path_tetragon(struct path * path, char * buf,
                                               size_t sz)
{
    int size = 0, error = 0;
    char * fullpath = d_path_local(path, &size, &error);
    if (!fullpath) {
        return -1;
    }
    // make the ebpf verifier happy
    asm volatile("%[size] &= 0xfff;\n" : [size] "+r"(size));
    probe_read(buf, size, fullpath);
    // d_path_local does not null-terminate.
    buf[size] = '\0';
    size++;
    return size;
}

static __always_inline void debug_path_d(struct path * filename,
                                         bool use_bpf_d_path)
{
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u32 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (!event) {
        return;
    }
    if (use_bpf_d_path)
        bpf_d_path(filename, event->data, sizeof(event->data));

    event_data_t * event2 =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (!event2) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_d_path_tetragon(filename, event2->data, sizeof(event2->data));

    bpf_printk("debug_path_d mntns=%u comm=%s\n bpf_d_path=%s\n tetra_path=%s",
               mntns, comm, event->data, event2->data);
    bpf_ringbuf_discard(event, 0);
    bpf_ringbuf_discard(event2, 0);
}

static u64 _file_event_inode;
static u64 _file_event_flags;
static u32 _file_event_pid;

static __always_inline int register_fs_event(struct path * filename,
                                             umode_t i_mode, u64 flags,
                                             bool custom_bpf_d_path)
{
    // ignore unix pipes
    if ((i_mode & S_IFMT) == S_IFIFO) {
        return 0;
    }

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    u64 inode_number = BPF_CORE_READ(filename, dentry, d_inode, i_ino);

    // discard repeated calls
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool same_file = inode_number && inode_number == _file_event_inode &&
                     pid == _file_event_pid;
    bool flags_are_subset = (flags | _file_event_flags) == _file_event_flags;
    if (same_file && flags_are_subset) {
        // very noisy
        // trace_hook("register_file_event skipped");
        return 0;
    }

    event_data_t * event;
    event = bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (!event) {
        return 0;
    }

    int pathlen;
    // Some BPF hooks cannot use bpf_d_path, for these cases we swap in our own
    // implementation.
    if (custom_bpf_d_path) {
        pathlen =
            bpf_d_path_tetragon(filename, event->data, sizeof(event->data));
    } else {
        pathlen = bpf_d_path(filename, event->data, sizeof(event->data));
    }
    if (pathlen < 0) {
        bpf_printk("register_file_event bpf_d_path failed: %i", pathlen);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    if ((i_mode & S_IFMT) == S_IFDIR) {
        // Somehow this makes the verifier happy.
        u16 idx = pathlen - 1;
        if (idx < sizeof(event->data) - sizeof(FORWARD_SLASH)) {
            bpf_core_read(event->data + idx, sizeof(FORWARD_SLASH),
                          &FORWARD_SLASH);
        } else {
            // pathlen is close to PATH_MAX.
            bpf_printk(
                "failed to fixup directory entry, pathlen is too close to "
                "PATH_MAX: %s",
                event->data);
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }

    event->pid = pid;
    event->mntns = mntns;
    event->type = EVENT_TYPE_APPARMOR_FILE;
    event->flags = flags;

    trace_hook("register_file_event: %s with flags=%d, i_mode=%d", event->data,
               flags, i_mode);
    bpf_ringbuf_submit(event, 0);

    if (inode_number) {
        _file_event_inode = inode_number;
        _file_event_pid = pid;
        _file_event_flags = same_file ? (flags | _file_event_flags) : flags;
    }

    return 0;
}

static __always_inline int register_file_event(struct file * file, u64 flags)
{
    if (file == NULL) {
        return 0;
    }
    return register_fs_event(&file->f_path, file->f_inode->i_mode, flags,
                             false);
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file * file)
{
    if (!_is_recording_cached)
        return 0;
    trace_hook("file_open");
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
    if (!_is_recording_cached)
        return 0;
    // very noisy
    // trace_hook("file_lock");
    return register_file_event(file, FLAG_WRITE);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file * file, unsigned long prot,
             unsigned long flags)
{
    if (!_is_recording_cached)
        return 0;
    trace_hook("mmap_file");
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
    if (!_is_recording_cached)
        return 0;
    trace_hook("bprm_check_security");
    return register_file_event(bprm->file, FLAG_SPAWN);
}

SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, struct path * dir, struct dentry * dentry,
             umode_t mode)
{
    if (!_is_recording_cached)
        return 0;
    trace_hook("path_mkdir");
    struct path filename = make_path(dentry, dir);
    return register_fs_event(&filename, mode | S_IFDIR, FLAG_READ | FLAG_WRITE,
                             true);
}

SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, struct path * dir, struct dentry * dentry,
             umode_t mode, unsigned int dev)
{
    if (!_is_recording_cached)
        return 0;
    trace_hook("path_mknod %d", mode);
    umode_t filetype = mode & S_IFMT;
    bool not_a_regular_file = (filetype == S_IFCHR || filetype == S_IFBLK ||
                               filetype == S_IFIFO || filetype == S_IFSOCK);
    umode_t file_flags = FLAG_WRITE;
    if (not_a_regular_file) {
        file_flags |= FLAG_READ;
    }
    struct path path = make_path(dentry, dir);
    return register_fs_event(&path, 0, file_flags, true);
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path * dir, struct dentry * dentry)
{
    if (!_is_recording_cached)
        return 0;
    trace_hook("path_unlink");
    struct path path = make_path(dentry, dir);
    return register_fs_event(&path, 0, FLAG_READ | FLAG_WRITE, true);
}

SEC("tracepoint/syscalls/sys_enter_socket")
int sys_enter_socket(struct trace_event_raw_sys_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_socket");

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    event_data_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_data_t), 0);
    if (event) {
        event->pid = pid;
        event->mntns = mntns;
        event->type = EVENT_TYPE_APPARMOR_SOCKET;

        u64 type;
        int res;
        res = bpf_core_read(&type, sizeof(type), &ctx->args[1]);
        if (res != 0) {
            bpf_printk("failed to get socket type");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        event->flags = type;

        trace_hook("requesting raw socket");
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(cap_capable)
{
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    unsigned long cap = PT_REGS_PARM3(ctx);
    unsigned long cap_opt = PT_REGS_PARM4(ctx);
    trace_hook("requesting capability: cap=%i cap_opt=%i", cap, cap_opt);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;
    if (is_runc_init())  // there are some SYS_ADMIN privileges exercised after
                         // sys_enter_execve
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

SEC("tracepoint/syscalls/sys_enter_prctl")
int sys_enter_prctl(struct trace_event_raw_sys_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_prctl");

    // Handle runc init.
    //
    // Hooking here:
    // https://github.com/opencontainers/runc/blob/81b13172bea2e6e4cf50f6bdd29a5fdeb5a6acf5/libcontainer/standard_init_linux.go#L148
    if (ctx->args[0] == PR_GET_PDEATHSIG && is_runc_init()) {
        clear_mntns_seccomp(mntns);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_execve");

    // Handle runc init.
    //
    // Hooking here:
    // https://github.com/opencontainers/runc/blob/81b13172bea2e6e4cf50f6bdd29a5fdeb5a6acf5/libcontainer/standard_init_linux.go#L288
    if (is_runc_init()) {
        clear_mntns_apparmor(mntns);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec * ctx)
{
    if (!_is_recording_cached)
        return 0;
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
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ok = bpf_map_delete_elem(&active_pids, &pid);
    if (ok != 0) {
        return 0;  // key not found
    }
    trace_hook("removing child pid: %u", pid);
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
    if (!_is_recording_cached)
        return 0;
    u32 ret = ctx->ret;
    // We only need the fork, the existing process is already traced.
    if (ret == 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool is_child = bpf_map_lookup_elem(&child_pids, &pid) != NULL;
    if (is_child) {
        trace_hook("adding child pid from clone: %u", ret);
        bpf_map_update_elem(&child_pids, &ret, &TRUE, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter * args)
{
    if (!_is_recording_cached)
        return 0;
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
            trace_hook("new pid observed: %u, mntns: %u", pid, mntns);

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
                "look up item in mntns_syscalls map failed pid: %u, mntns: %u",
                pid, mntns);
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}

// Hooking a rarely used syscall to refresh `_is_recording_cached`.
// This is (hopefully) more efficient than calling `bpf_map_lookup_elem` on
// every hook.
SEC("tracepoint/syscalls/sys_enter_getgid")
int sys_enter_getgid(struct trace_event_raw_sys_enter * ctx)
{
    const int key = 0;
    bool * value = bpf_map_lookup_elem(&is_recording, &key);
    _is_recording_cached = value && *value;
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
