#include <vmlinux.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_COMM_LEN 64
#define MAX_MNTNS_LEN 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);                 // mntns
    __type(value, u8[MAX_SYSCALLS]);  // syscall IDs
} mntns_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                   // PID
    __type(value, char[MAX_COMM_LEN]);  // command name
} comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MNTNS_LEN);
    __type(key, u32);                   // PID
    __type(value, u64);                 // mntns ID
} system_mntns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);                   // mntns id
    __type(value, u8);                  // is mntns record
} mntns_record SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
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
    // Filter mntns by hostmntns to exclude host processes
    u32 hostPid = 1;
    u64 * host_mntns;
    host_mntns = bpf_map_lookup_elem(&system_mntns, &hostPid);
    if (host_mntns != NULL && *host_mntns == mntns) {
        return 0;
    }

    // Update the command name if required
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&comms, &pid) == NULL) {
        bpf_map_update_elem(&comms, &pid, &comm, BPF_ANY);
    }

    // Update the syscalls
    u8 * const mntns_syscall_value = bpf_map_lookup_elem(&mntns_syscalls, &mntns);
    if (mntns_syscall_value) {
        mntns_syscall_value[syscall_id] = 1;
        u8 * isRecord;
        isRecord = bpf_map_lookup_elem(&mntns_record, &mntns);
        if (isRecord == NULL) {
            // New element, throw event
            struct event_t * event_again =
                    bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
            if (!event_again) {
                // Not enough space within the ringbuffer
                return 0;
            }
            event_again->pid = pid;
            event_again->mntns = mntns;
            bpf_ringbuf_submit(event_again, 0);
            bpf_printk("send event again pid: %d , mntns: %u, comm: %s\n", pid, mntns, comm);
            return 0;
        } else {
            bpf_printk("mntns_record not send mntns: %u, isRecord: %u\n", mntns, *isRecord);
            return 0;
        }
    } else {

        // New element, throw event
        struct event_t * event =
                bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (!event) {
            // Not enough space within the ringbuffer
            return 0;
        }

        event->pid = pid;
        event->mntns = mntns;

        bpf_ringbuf_submit(event, 0);
        bpf_printk("send event bpf_ringbuf_submit pid: %d , mntns: %u, comm: %s\n", pid, mntns, comm);
        static const char init[MAX_SYSCALLS];
        bpf_map_update_elem(&mntns_syscalls, &mntns, &init, BPF_ANY);

        u8 * const value = bpf_map_lookup_elem(&mntns_syscalls, &mntns);
        if (!value) {
            bpf_printk("bpf_map_lookup_elem failed pid: %d , mntns: %u, comm: %s\n", pid, mntns, comm);
            // Should not happen, we updated the element straight ahead
            return 0;
        }
        value[syscall_id] = 1;
    }

    return 0;
}
