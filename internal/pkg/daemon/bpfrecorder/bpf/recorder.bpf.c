#include <vmlinux.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_COMM_LEN 64

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

struct event_t {
    u32 pid;
    u32 mntns;
};

const volatile char filter_name[MAX_COMM_LEN] = {};

static inline bool is_filtered(char * comm);

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter * args)
{
    // Sanity check for syscall ID range
    u32 syscall_id = args->id;
    if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

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
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (is_filtered(comm)) {
        return 0;
    }

    // Notify the userspace when a new PID is found. This will allow
    // the userspace to look up the container ID from cgroups of the
    // process. And using the container ID, it will search futher the
    // security profile assigned to this container in the cluster.
    u32 * current_pid_mntns = NULL;
    current_pid_mntns = bpf_map_lookup_elem(&pid_mntns, &pid);
    if (current_pid_mntns == NULL) {
        struct event_t * event =
            bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (event) {
            bpf_printk("send event pid: %u, mntns: %u, comm: %s\n", pid, mntns,
                       comm);

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
                "look up item in mntns_syscalls map failed pid: %u, mntns: %u, "
                "comm: %s\n",
                pid, mntns, comm);
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}

static inline bool is_filtered(char * comm)
{
    // No filter set
    if (filter_name[0] == 0) {
        return false;
    }

    // We cannot use __builtin_memcmp() until llvm bug
    // https://llvm.org/bugs/show_bug.cgi?id=26218 got resolved
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        if (comm[i] != filter_name[i]) {
            return true;
        }

        // Stop searching when comm is done
        if (comm[i] == 0) {
            break;
        }
    }

    return false;
}
