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
// The per workload bookkeeping maps are larger than the data maps, so that
// they keep track of excluded workloads well past the recorded ones.
#define MAX_TRACKED_KEYS 32 * 1024

// We don't have TASK_COMM_LEN in userspace, so we define
// a static MAX_COMM_LEN which is supposed to be >= TASK_COMM_LEN
#define MAX_COMM_LEN 1024

#define EVENT_TYPE_NEWPID 0
#define EVENT_TYPE_EXIT 1
#define EVENT_TYPE_APPARMOR_FILE 2
#define EVENT_TYPE_APPARMOR_SOCKET 3
#define EVENT_TYPE_APPARMOR_CAP 4
#define EVENT_TYPE_CLEAR_MNTNS 5
#define EVENT_TYPE_EXECVE_ENTER 6

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

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

// The syscalls the container start is detected with, see is_container_init.
// Their numbers are not part of vmlinux.h.
#if defined(__TARGET_ARCH_x86)
#define NR_EXECVE 59
#define NR_EXECVEAT 322
#define NR_PRCTL 157
#define NR_SECCOMP 317
#elif defined(__TARGET_ARCH_arm64)
#define NR_EXECVE 221
#define NR_EXECVEAT 281
#define NR_PRCTL 167
#define NR_SECCOMP 277
#else
#define NR_EXECVE -1
#define NR_EXECVEAT -1
#define NR_PRCTL -1
#define NR_SECCOMP -1
#endif

#define PR_GET_PDEATHSIG 2
#define PR_SET_SECCOMP 22
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2

// The number of container init process names the userspace can pass.
#define MAX_INIT_COMMS 4
// The length of the executable name prefix of container init processes the
// userspace can pass, including the terminating NUL byte.
#define INIT_EXE_PREFIX_LEN 32

// A 32 bit task on a 64 bit kernel, see is_compat_task.
#define TS_COMPAT 0x0002
#define TIF_32BIT 22

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

// toggle this for additional debug output
#define trace_hook(...)
// #define trace_hook(...) if(get_mntns()) { bpf_printk(__VA_ARGS__); }

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

// Track syscalls per recording key, see get_key.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);                 // recording key
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} recorded_syscalls SEC(".maps");

// Keys of workloads which are not recorded, see get_mntns. Only used with
// keys which are never reused, see unique_keys.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_KEYS);
    __type(key, u64);
    __type(value, u8);
} exclude_keys SEC(".maps");

// A process together with the key it records under. The threads of a process
// can record under different keys, for example after one of them unshared its
// mount namespace.
struct pid_key {
    u32 pid;
    u32 pad;
    u64 key;
};

// Track active (known) processes and the keys they recorded under. This is an
// LRU map, because the userspace only clears it when a recording starts or
// stops: a full map must evict stale entries instead of failing every insert.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct pid_key);
    __type(value, u8);
} active_pids SEC(".maps");

// Keys whose container initialization has been seen. The runtime init process
// also runs for every exec into a running container, which must not clear the
// data recorded for it so far.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_KEYS);
    __type(key, u64);
    __type(value, u8);
} seccomp_initialized SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_KEYS);
    __type(key, u64);
    __type(value, u8);
} apparmor_initialized SEC(".maps");

// The capabilities reported per recording key, as a bitmask of the capability
// numbers. A workload checks the same capability over and over again, which
// only has to be reported once. The entries are dropped when the recorded
// data of the key is cleared, so that the following uses get reported again.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} recorded_caps SEC(".maps");

// The sockets reported per recording key, as a bitmask, see socket_bit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} recorded_sockets SEC(".maps");

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

// Counts recorded data the kernel side had to drop, per reason. The userspace
// sums the per CPU values and reports them.
#define LOST_RINGBUF 0
#define LOST_SYSCALLS_MAP_FULL 1
#define LOST_FILE_EVENT_BUSY 2
#define LOST_COMPAT_SYSCALL 3
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u64);
} lost_events SEC(".maps");

// Max number of arguments/env vars to capture
#define MAX_ARGS 20
#define MAX_ENV 50
// Max length for each argument/env var string
#define MAX_FILENAME_LEN 128
#define MAX_ARG_LEN 64
#define MAX_ENV_LEN 64

// Every event starts with this header. Events which carry no data are sent as
// the header alone, so that they only take a few bytes of the ring buffer.
typedef struct __attribute__((__packed__)) event_header {
    u32 pid;
    u32 mntns;
    u64 key;
    u8 type;
    u64 flags;
} event_header_t;

// File events are sent with the header and as much of data as the path needs.
typedef struct __attribute__((__packed__)) event_data {
    event_header_t hdr;
    char data[PATH_MAX];
} event_data_t;

// The exec event is only used by the process cache, see capture_exec_args.
typedef struct __attribute__((__packed__)) exec_event_data {
    event_header_t hdr;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_ARG_LEN];
    char env[MAX_ENV][MAX_ENV_LEN];
    u32 args_len;
    u32 env_len;
} exec_event_data_t;

// File events are assembled here before they are copied into the ring buffer
// with their actual size.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, event_data_t);
} file_event_scratch SEC(".maps");

// The last file event sent per thread, used to discard repeated accesses.
// Keeping it per thread makes the result independent of the CPUs a process
// runs on, and a thread cannot preempt itself in the middle of an update.
struct file_event_state {
    u64 inode;
    u64 flags;
    u32 dev;
    // overlay is set if the file is on an overlay file system.
    u32 overlay;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);  // thread ID
    __type(value, struct file_event_state);
} last_file_event SEC(".maps");

// The LSM hooks run with migration disabled, but can be preempted by another
// task running the same hook on this CPU. busy makes sure that only one of
// them uses the per CPU scratch buffer at a time.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} file_event_busy SEC(".maps");

const volatile char filter_name[MAX_COMM_LEN] = {};

// Identify the recorded workload by its cgroup instead of its mount namespace.
// Set by the userspace on cgroup v2 hosts: cgroup IDs are never reused, while
// mount namespace inode numbers are handed out again as soon as they are free.
const volatile bool use_cgroup_id = false;

// Identify the recorded workload by the sequence number of its mount
// namespace, which is never reused either. Set by the userspace for hosts
// without cgroup v2.
const volatile bool use_mntns_seq = false;

// Send the arguments and environment of every execve to the userspace. Only
// the process cache needs them, the recorder would just waste ring buffer
// space on them.
const volatile bool capture_exec_args = false;

// The names of the processes the container runtimes start a container with,
// like runc:[2:INIT] or crun, set by the userspace. Their first exec under a
// key is the start of the container, see is_container_init. They are matched
// exactly. Unused entries are empty.
const volatile char init_comms[MAX_INIT_COMMS][TASK_COMM_LEN] = {};

// The prefix of the name of the executable file of a container init process
// whose name is a number, set by the userspace, see is_container_init. Empty
// if unused.
const volatile char init_exe_prefix[INIT_EXE_PREFIX_LEN] = {};

static const char FORWARD_SLASH[] = "/";
static const bool TRUE = true;
static inline bool has_filter();
static inline bool matches_filter(char * comm);

// The unique mount namespace ID moved between kernel versions: older ones
// have a sequence number in the mount namespace, newer ones an ID in the
// common namespace structure.
struct mnt_namespace___seq {
    u64 seq;
} __attribute__((preserve_access_index));

struct ns_common___id {
    u64 ns_id;
} __attribute__((preserve_access_index));

struct mnt_namespace___id {
    struct ns_common___id ns;
} __attribute__((preserve_access_index));

// get_mntns_id returns the ID of the current mount namespace, which is never
// reused, unlike its inode number. It falls back to the inode number if the
// kernel has neither.
static __always_inline u64 get_mntns_id(u32 mntns)
{
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    struct mnt_namespace * ns = BPF_CORE_READ(task, nsproxy, mnt_ns);

    if (bpf_core_field_exists(struct mnt_namespace___seq, seq)) {
        return BPF_CORE_READ((struct mnt_namespace___seq *)ns, seq);
    }
    if (bpf_core_field_exists(struct mnt_namespace___id, ns.ns_id)) {
        return BPF_CORE_READ((struct mnt_namespace___id *)ns, ns.ns_id);
    }
    return mntns;
}

/**
 * get_key returns the key the recorded data of the current process is stored
 * under. This is the cgroup ID or the mount namespace sequence number if
 * selected, and the mount namespace otherwise.
 */
static __always_inline u64 get_key(u32 mntns)
{
    if (use_cgroup_id) {
        return bpf_get_current_cgroup_id();
    }
    if (use_mntns_seq) {
        return get_mntns_id(mntns);
    }
    return mntns;
}

// unique_keys reports whether a key is never used for another workload.
static __always_inline bool unique_keys()
{
    return use_cgroup_id || use_mntns_seq;
}

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

    // Filter out the workloads the userspace found not to be recorded.
    if (unique_keys()) {
        u64 key = get_key(mntns);
        if (bpf_map_lookup_elem(&exclude_keys, &key) != NULL) {
            return 0;
        }
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

static __always_inline void count_lost(u32 reason)
{
    u64 * lost = bpf_map_lookup_elem(&lost_events, &reason);
    if (lost) {
        *lost += 1;
    }
}

// Send an event which carries no data besides its header.
static __always_inline int submit_event(u8 type, u32 mntns, u64 key, u64 flags)
{
    event_header_t * event =
        bpf_ringbuf_reserve(&events, sizeof(event_header_t), 0);
    if (!event) {
        count_lost(LOST_RINGBUF);
        return -1;
    }
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->mntns = mntns;
    event->key = key;
    event->type = type;
    event->flags = flags;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// clear_seccomp drops the syscalls recorded during the container
// initialization. Only the first initialization of a key is the container
// start, the later ones are execs into the running container.
static __always_inline u32 clear_seccomp(u64 key)
{
    // A reused key belongs to another workload, which has to be cleared on
    // its start again.
    static const u8 one = 1;
    if (unique_keys() && bpf_map_update_elem(&seccomp_initialized, &key, &one,
                                             BPF_NOEXIST) != 0) {
        return 0;
    }
    trace_hook("clear_seccomp key=%llu", key);
    bpf_map_delete_elem(&recorded_syscalls, &key);
    return 0;
}

// clear_apparmor is clear_seccomp for the AppArmor data, which the userspace
// holds.
static __always_inline u32 clear_apparmor(u32 mntns, u64 key)
{
    static const u8 one = 1;
    if (unique_keys() && bpf_map_update_elem(&apparmor_initialized, &key, &one,
                                             BPF_NOEXIST) != 0) {
        return 0;
    }
    trace_hook("clear_apparmor key=%llu", key);
    if (submit_event(EVENT_TYPE_CLEAR_MNTNS, mntns, key, 0) != 0) {
        // Try again with the next hook call.
        if (unique_keys()) {
            bpf_map_delete_elem(&apparmor_initialized, &key);
        }
        return -1;
    }
    // The userspace drops what it recorded, so the capabilities and sockets
    // have to be reported again.
    bpf_map_delete_elem(&recorded_caps, &key);
    bpf_map_delete_elem(&recorded_sockets, &key);
    return 0;
}

// is_exec_syscall reports whether the syscall replaces the program of the
// calling process.
static __always_inline bool is_exec_syscall(u32 syscall_id)
{
    return syscall_id == NR_EXECVE || syscall_id == NR_EXECVEAT;
}

// is_seccomp_install reports whether the syscall installs a seccomp filter.
// Only what a container does once its filter is installed has to be in its
// profile, everything the runtime did before is setup.
//
// A profile is usually recorded without any filter, so the prctl runc issues
// right before it would install one is taken as well, see
// https://github.com/opencontainers/runc/blob/v1.3.0/libcontainer/standard_init_linux.go#L146
// crun and youki have no such marker, their setup stays in the profile when
// no filter is installed while recording.
//
// libseccomp, which runc uses, probes the kernel with calls the kernel
// rejects during the setup, which are no install: a strict mode with flags,
// see sys_chk_seccomp_syscall, and a filter without a filter program, see
// sys_chk_seccomp_flag in libseccomp.
static __always_inline bool is_seccomp_install(
    u32 syscall_id, struct trace_event_raw_sys_enter * args)
{
    if (syscall_id == NR_SECCOMP) {
        u64 operation = args->args[0];
        if (operation == SECCOMP_SET_MODE_STRICT) {
            return args->args[1] == 0 && args->args[2] == 0;
        }
        return operation == SECCOMP_SET_MODE_FILTER && args->args[2] != 0;
    }
    if (syscall_id == NR_PRCTL) {
        u64 option = args->args[0];
        if (option == PR_SET_SECCOMP) {
            return args->args[1] == SECCOMP_MODE_STRICT ||
                   (args->args[1] == SECCOMP_MODE_FILTER && args->args[2] != 0);
        }
        return option == PR_GET_PDEATHSIG;
    }
    return false;
}

// already_recorded marks bit in the bitmask of key and reports whether it
// was set before. An event is reported if the mask cannot be tracked, which
// only costs the userspace a repeated event.
static __always_inline bool already_recorded(void * mask_map, u64 key, u64 bit)
{
    u64 * mask = bpf_map_lookup_elem(mask_map, &key);
    if (!mask) {
        static const u64 zero = 0;
        bpf_map_update_elem(mask_map, &key, &zero, BPF_NOEXIST);
        mask = bpf_map_lookup_elem(mask_map, &key);
        if (!mask) {
            return false;
        }
    }
    return (__sync_fetch_and_or(mask, bit) & bit) != 0;
}

// report_again clears bit in the bitmask of key, so that the next use is
// reported again after the event got lost.
static __always_inline void report_again(void * mask_map, u64 key, u64 bit)
{
    u64 * mask = bpf_map_lookup_elem(mask_map, &key);
    if (mask) {
        __sync_fetch_and_and(mask, ~bit);
    }
}

// is_compat_task reports whether the current task uses the 32 bit syscall ABI.
// Its syscall numbers are the ones of that ABI, which the userspace would
// record as the native syscalls with the same numbers.
static __always_inline bool is_compat_task()
{
#if defined(__TARGET_ARCH_x86)
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    return (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
#elif defined(__TARGET_ARCH_arm64)
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    return (BPF_CORE_READ(task, thread_info.flags) & (1UL << TIF_32BIT)) != 0;
#else
    return false;
#endif
}

// is_number reports whether comm is a non-negative decimal number.
static __always_inline bool is_number(const char * comm)
{
    if (comm[0] == 0) {
        return false;
    }
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (comm[i] == 0) {
            return true;
        }
        if (comm[i] < '0' || comm[i] > '9') {
            return false;
        }
    }
    return true;
}

// exe_has_init_prefix reports whether the name of the executable file of the
// current process starts with init_exe_prefix.
static __always_inline bool exe_has_init_prefix()
{
    if (init_exe_prefix[0] == 0) {
        return false;
    }

    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    const unsigned char * name =
        BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name);
    if (!name) {
        return false;
    }

    char exe[INIT_EXE_PREFIX_LEN] = {};
    if (bpf_probe_read_kernel_str(exe, sizeof(exe), name) < 0) {
        return false;
    }

    for (int i = 0; i < INIT_EXE_PREFIX_LEN; i++) {
        if (init_exe_prefix[i] == 0) {
            return true;
        }
        if (exe[i] != init_exe_prefix[i]) {
            return false;
        }
    }
    return true;
}

// is_container_init reports whether the current process is the one a
// container runtime starts a container with. Its exec of the entrypoint is
// the container start, and the syscalls, files and capabilities of the
// runtime setup before it are not part of the workload.
//
// runc and youki name the process, crun keeps the name of its executable.
// Unless its binary is on a read-only file system, crun executes a copy of
// itself from a memfd, see ensure_cloned_binary in crun. Since Linux 6.14 the
// process is named after the memfd then, memfd:crun_cloned:/proc/self/exe cut
// to memfd:crun_clon. Older kernels name it after the number of the file
// descriptor it got executed from, which is recognized by the name of the
// memfd, init_exe_prefix.
static __always_inline bool is_container_init()
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    for (int n = 0; n < MAX_INIT_COMMS; n++) {
        if (init_comms[n][0] == 0) {
            // The entries are filled from the start.
            break;
        }
        bool matches = true;
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (comm[i] != init_comms[n][i]) {
                matches = false;
                break;
            }
            if (comm[i] == 0) {
                break;
            }
        }
        if (matches) {
            return true;
        }
    }

    // Only a process named after a number is looked at further, as reading
    // the name of its executable costs more than comparing its name.
    return is_number(comm) && exe_has_init_prefix();
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

// register_fs_event_locked sends a file event. The caller owns the per CPU
// state last and event.
static __always_inline void register_fs_event_locked(
    struct path * filename, umode_t i_mode, u64 flags, bool custom_bpf_d_path,
    u32 mntns, u32 pid, u64 inode_number, u32 dev, bool overlay,
    event_data_t * event)
{
    // Discard repeated calls of the same thread. Inode numbers are only
    // unique per file system, so the device is part of the comparison.
    //
    // Opening a file on overlayfs opens the file of the layer beneath it
    // right away, with the same inode number on another device. Its path is
    // the one within the layer, which the workload never uses, so it is
    // discarded as well.
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct file_event_state * last =
        bpf_map_lookup_elem(&last_file_event, &tid);
    bool same_file = last && inode_number && inode_number == last->inode &&
                     (dev == last->dev || (last->overlay && !overlay));
    if (same_file && (flags | last->flags) == last->flags) {
        // very noisy
        // trace_hook("register_file_event skipped");
        return;
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
        return;
    }

    if ((i_mode & S_IFMT) == S_IFDIR) {
        // Somehow this makes the verifier happy.
        u16 idx = pathlen - 1;
        if (idx < sizeof(event->data) - sizeof(FORWARD_SLASH)) {
            bpf_core_read(event->data + idx, sizeof(FORWARD_SLASH),
                          &FORWARD_SLASH);
            pathlen++;
        } else {
            // pathlen is close to PATH_MAX.
            bpf_printk(
                "failed to fixup directory entry, pathlen is too close to "
                "PATH_MAX: %s",
                event->data);
            return;
        }
    }

    event->hdr.pid = pid;
    event->hdr.mntns = mntns;
    event->hdr.key = get_key(mntns);
    event->hdr.type = EVENT_TYPE_APPARMOR_FILE;
    event->hdr.flags = flags;

    trace_hook("register_file_event: %s with flags=%d, i_mode=%d", event->data,
               flags, i_mode);

    // Only send the part of the path buffer which is in use.
    u64 size = sizeof(event_header_t) + pathlen;
    asm volatile("%[size] &= 0x1fff;\n" : [size] "+r"(size));
    if (size > sizeof(event_data_t)) {
        size = sizeof(event_data_t);
    }
    if (bpf_ringbuf_output(&events, event, size, 0) != 0) {
        count_lost(LOST_RINGBUF);
        return;
    }

    if (!inode_number) {
        return;
    }

    if (last) {
        last->flags = same_file ? (flags | last->flags) : flags;
        last->inode = inode_number;
        last->dev = dev;
        last->overlay = overlay;
        return;
    }

    struct file_event_state state = {
        .inode = inode_number,
        .flags = flags,
        .dev = dev,
        .overlay = overlay,
    };
    bpf_map_update_elem(&last_file_event, &tid, &state, BPF_ANY);
}

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

    struct inode * inode = BPF_CORE_READ(filename, dentry, d_inode);
    u64 inode_number = BPF_CORE_READ(inode, i_ino);
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    bool overlay = BPF_CORE_READ(inode, i_sb, s_magic) == OVERLAYFS_SUPER_MAGIC;

    u32 zero = 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 * busy = bpf_map_lookup_elem(&file_event_busy, &zero);
    event_data_t * event = bpf_map_lookup_elem(&file_event_scratch, &zero);
    if (!busy || !event) {
        return 0;
    }

    // Another task preempted on this CPU is using the scratch buffer. The
    // counter is only changed with atomic adds, which need no newer BPF
    // instruction set than the fetching ones. At most one task reads 1 after
    // its increment, the others back off until it is done.
    __sync_fetch_and_add(busy, 1);
    if (READ_ONCE(*busy) != 1) {
        __sync_fetch_and_add(busy, -1);
        count_lost(LOST_FILE_EVENT_BUSY);
        return 0;
    }

    register_fs_event_locked(filename, i_mode, flags, custom_bpf_d_path, mntns,
                             pid, inode_number, dev, overlay, event);

    __sync_fetch_and_add(busy, -1);
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

// The per syscall tracepoints, like syscalls/sys_enter_socket, pass a struct
// syscall_trace_enter instead of the struct trace_event_raw_sys_enter of
// raw_syscalls/sys_enter. Its syscall number is an int instead of a long, so
// the arguments follow at another offset if the common fields do not end on
// an 8 byte boundary, like on PREEMPT_RT kernels. CO-RE relocates the
// arguments against the kernel layout of the struct.
SEC("tracepoint/syscalls/sys_enter_socket")
int sys_enter_socket(struct syscall_trace_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_socket");

    u64 domain, type;
    if (bpf_core_read(&domain, sizeof(domain), &ctx->args[0]) != 0) {
        bpf_printk("failed to get socket domain");
        return 0;
    }
    if (bpf_core_read(&type, sizeof(type), &ctx->args[1]) != 0) {
        bpf_printk("failed to get socket type");
        return 0;
    }

    trace_hook("requesting socket domain %llu type %llu", domain, type);

    // Report every kind of socket once per key. The userspace only tells the
    // unix and internet domains apart, and the socket type without its
    // SOCK_NONBLOCK and SOCK_CLOEXEC flags, so the bitmask groups the sockets
    // the same way.
    u64 group;
    if (domain == AF_UNIX) {
        group = 0;
    } else if (domain == AF_INET) {
        group = 1;
    } else if (domain == AF_INET6) {
        group = 2;
    } else {
        group = 3;
    }
    u64 bit = 1ULL << (group * 16 + (type & 0xf));
    u64 key = get_key(mntns);
    if (already_recorded(&recorded_sockets, key, bit)) {
        return 0;
    }

    // The domain goes into the upper half of the flags, the type together
    // with its SOCK_NONBLOCK and SOCK_CLOEXEC flags into the lower one.
    if (submit_event(EVENT_TYPE_APPARMOR_SOCKET, mntns, key,
                     (domain << 32) | (type & 0xffffffff)) != 0) {
        report_again(&recorded_sockets, key, bit);
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
    if (is_container_init())  // there are some SYS_ADMIN privileges exercised
                              // by the runtime after the exec of the container
        return 0;
    if (cap >= 64)  // the bitmask holds the capabilities the kernel has
        return 0;

    // Report every capability once per key.
    u64 bit = 1ULL << cap;
    u64 key = get_key(mntns);
    if (already_recorded(&recorded_caps, key, bit)) {
        return 0;
    }

    if (submit_event(EVENT_TYPE_APPARMOR_CAP, mntns, key, cap) != 0) {
        report_again(&recorded_caps, key, bit);
    }

    return 0;
}

static __always_inline void submit_exec_event(const __u8 * filename,
                                              const __u8 * const * argv,
                                              const __u8 * const * envp,
                                              u32 mntns)
{
    exec_event_data_t * exec_event =
        bpf_ringbuf_reserve(&events, sizeof(exec_event_data_t), 0);
    if (!exec_event) {
        count_lost(LOST_RINGBUF);
        return;
    }

    const __u8 * ptr;
    int ret;
    u32 count = 0;

    exec_event->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    exec_event->hdr.mntns = mntns;
    exec_event->hdr.key = get_key(mntns);
    exec_event->hdr.type = EVENT_TYPE_EXECVE_ENTER;
    exec_event->hdr.flags = 0;

    // Get filename (first argument)
    bpf_probe_read_user_str(&exec_event->filename, sizeof(exec_event->filename),
                            (void *)filename);

    // Read argv
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        // Read pointer to the argument string
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &argv[i]);
        if (ret < 0 || !ptr) {
            break;  // End of arguments
        }

        // Read the argument string into our buffer
        ret = bpf_probe_read_user_str(exec_event->args[i],
                                      sizeof(exec_event->args[i]), ptr);
        if (ret < 0) {
            break;
        }
        count++;
    }

    exec_event->args_len = count;  // Store actual length of args data

    count = 0;

#pragma unroll
    for (int i = 0; i < MAX_ENV; i++) {
        // Read pointer to the environment string
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &envp[i]);
        if (ret < 0 || !ptr) {
            break;
        }

        // Read the env string into our buffer
        ret = bpf_probe_read_user_str(exec_event->env[i],
                                      sizeof(exec_event->env[i]), ptr);
        if (ret < 0) {
            break;
        }
        count++;
    }

    exec_event->env_len = count;  // Store actual length of env data

    bpf_ringbuf_submit(exec_event, 0);
}

// The exec tracepoints only serve the process cache, see capture_exec_args.
// The container start is detected in sys_enter, which sees the exec syscalls
// as well. The arguments are read through the CO-RE relocated tracepoint
// context, as the layout of its common fields differs between kernels, see
// sys_enter_socket.
SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_trace_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    if (!capture_exec_args)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_execve");

    submit_exec_event((const __u8 *)ctx->args[0],
                      (const __u8 * const *)ctx->args[1],
                      (const __u8 * const *)ctx->args[2], mntns);

    return 0;
}

// execveat is sys_enter_execve for programs started from a file descriptor or
// relative to a directory, like fexecve does.
SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(struct syscall_trace_enter * ctx)
{
    if (!_is_recording_cached)
        return 0;
    if (!capture_exec_args)
        return 0;
    u32 mntns = get_mntns();
    if (!mntns)
        return 0;
    trace_hook("sys_enter_execveat");

    submit_exec_event((const __u8 *)ctx->args[1],
                      (const __u8 * const *)ctx->args[2],
                      (const __u8 * const *)ctx->args[3], mntns);

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

    // child_pids holds thread group IDs, so the parent has to be looked up by
    // its thread group as well: a child can be spawned from any of its threads.
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u32 parent_tgid = BPF_CORE_READ(task, real_parent, tgid);
    bool is_child = bpf_map_lookup_elem(&child_pids, &parent_tgid) != NULL;

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

    // The tracepoint fires for every exiting thread, but the maps are keyed by
    // the thread group. Only the last thread to exit ends the process.
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;

    u32 mntns = get_mntns();
    if (!mntns)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_key active = {.pid = pid, .key = get_key(mntns)};
    if (bpf_map_delete_elem(&active_pids, &active) != 0) {
        return 0;  // key not found
    }
    trace_hook("removing child pid: %u", pid);
    bpf_map_delete_elem(&child_pids, &pid);

    submit_event(EVENT_TYPE_EXIT, mntns, get_key(mntns), 0);
    return 0;
}

// Add the processes forked by processes in child_pids to the map. Threads are
// left out, child_pids is keyed by thread group and they share the one of
// their process.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct * parent,
             struct task_struct * child)
{
    if (!_is_recording_cached)
        return 0;
    if (!has_filter())
        return 0;

    u32 child_pid = BPF_CORE_READ(child, pid);
    if (child_pid != BPF_CORE_READ(child, tgid))
        return 0;

    u32 parent_tgid = BPF_CORE_READ(parent, tgid);
    if (bpf_map_lookup_elem(&child_pids, &parent_tgid) != NULL) {
        trace_hook("adding child pid from fork: %u", child_pid);
        bpf_map_update_elem(&child_pids, &child_pid, &TRUE, BPF_ANY);
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
    u64 key = get_key(mntns);

    // Notify the userspace when a new process is found. This will allow
    // the userspace to look up the container ID from cgroups of the
    // process. And using the container ID, it will search further the
    // security profile assigned to this container in the cluster.
    //
    // Every key a process records under is reported, as a process can move
    // to another key after its first syscall, for example into a nested
    // cgroup or an unshared mount namespace, and its threads can record
    // under different keys. The lookup comes first, as it takes no lock
    // while updating the map does and this runs for every syscall.
    struct pid_key active = {.pid = pid, .key = key};
    bool reported = false;
    if (bpf_map_lookup_elem(&active_pids, &active) == NULL &&
        bpf_map_update_elem(&active_pids, &active, &TRUE, BPF_NOEXIST) == 0) {
        trace_hook("new pid observed: %u, mntns: %u", pid, mntns);
        if (submit_event(EVENT_TYPE_NEWPID, mntns, key, 0) != 0) {
            // Report the process with its next syscall instead of never.
            bpf_map_delete_elem(&active_pids, &active);
        } else {
            reported = true;
        }
    }

    // Syscalls of the 32 bit ABI would be recorded as the native ones with
    // the same numbers.
    if (is_compat_task()) {
        count_lost(LOST_COMPAT_SYSCALL);
        return 0;
    }

    // The container runtimes start a container with an init process which
    // sets up the container and then execs its entrypoint. The seccomp
    // profile only has to allow what runs once the filter is installed, and
    // the AppArmor profile only applies from the exec on, so what got
    // recorded before is dropped. Only the first time per key, later inits
    // are execs into the running container, see clear_seccomp.
    if ((is_exec_syscall(syscall_id) || is_seccomp_install(syscall_id, args)) &&
        is_container_init()) {
        if (is_exec_syscall(syscall_id)) {
            clear_apparmor(mntns, key);
        } else {
            clear_seccomp(key);
        }
    }

    // Record the syscall for this key
    u8 * value = bpf_map_lookup_elem(&recorded_syscalls, &key);
    if (!value) {
        // Initialise the syscalls recording buffer. Another CPU may have done
        // so concurrently, which is why an existing entry is not overwritten.
        static const char init[MAX_SYSCALLS];
        long err =
            bpf_map_update_elem(&recorded_syscalls, &key, &init, BPF_NOEXIST);
        if (err != 0 && err != -EEXIST) {
            count_lost(LOST_SYSCALLS_MAP_FULL);
            return 0;
        }
        // A new key of a known process is reported as well, so that the
        // userspace can exclude it again after its exclusion got evicted.
        if (err == 0 && !reported) {
            submit_event(EVENT_TYPE_NEWPID, mntns, key, 0);
        }
        value = bpf_map_lookup_elem(&recorded_syscalls, &key);
        if (!value) {
            // Removed again in between, e.g. by the runc init hook.
            return 0;
        }
    }
    value[syscall_id] = 1;

    return 0;
}

// Hooking a rarely used syscall to refresh `_is_recording_cached`.
// This is (hopefully) more efficient than calling `bpf_map_lookup_elem` on
// every hook.
SEC("tracepoint/syscalls/sys_enter_getgid")
int sys_enter_getgid(struct syscall_trace_enter * ctx)
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
