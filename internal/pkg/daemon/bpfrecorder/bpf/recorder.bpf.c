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
    __type(key, u32);                 // PID
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                   // PID
    __type(value, char[MAX_COMM_LEN]);  // command name
} comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_t {
    u64 pid;
    u64 mntns;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter * args)
{
    // Sanity check
    u32 syscall_id = args->id;
    if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (mntns == 0) {
        return 0;
    }

    // Update the command name if required
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&comms, &comm) == NULL) {
        bpf_map_update_elem(&comms, &pid, &comm, BPF_ANY);
    }

    // Update the syscalls
    u8 * const syscall_value = bpf_map_lookup_elem(&syscalls, &pid);
    if (syscall_value) {
        syscall_value[syscall_id] = 1;
    } else {
        // New element, throw event
        struct event_t event = {
            .pid = pid,
            .mntns = mntns,
        };
        bpf_perf_event_output(args, &events, 0, &event, sizeof(event));

        static const char init[MAX_SYSCALLS];
        bpf_map_update_elem(&syscalls, &pid, &init, BPF_ANY);

        u8 * const value = bpf_map_lookup_elem(&syscalls, &pid);
        if (!value) {
            // Should not happen, we updated the element straight ahead
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}
