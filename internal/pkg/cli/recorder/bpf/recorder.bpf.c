#include <vmlinux.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                 // PID
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} pids SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter * args)
{
    // Sanity check
    u32 syscall_id = args->id;
    if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Update the PIDs and syscalls
    u8 * const found = bpf_map_lookup_elem(&pids, &pid);
    if (found) {
        found[syscall_id] = 1;
    } else {
        static const char init[MAX_SYSCALLS];
        bpf_map_update_elem(&pids, &pid, &init, BPF_ANY);

        u8 * const value = bpf_map_lookup_elem(&pids, &pid);
        if (!value) {
            // Should not happen, we updated the element straight ahead
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}
