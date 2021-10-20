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
    __type(key, u64);                            // namespace
    __type(value, unsigned char[MAX_SYSCALLS]);  // syscall IDs
} syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);    // PID
    __type(value, u64);  // namespace
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);                   // PID
    __type(value, char[MAX_COMM_LEN]);  // command name
} comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void * lookup_or_init(void * map, const u64 key)
{
    void * const value = bpf_map_lookup_elem(map, &key);
    if (value) {
        return value;
    }

    static const char init[MAX_SYSCALLS];
    int err = bpf_map_update_elem(map, &key, &init, BPF_NOEXIST);
    if (err && err != -EEXIST) {
        return NULL;
    }

    return bpf_map_lookup_elem(map, &key);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit * args)
{
    // Sanity check
    u32 id = args->id;
    if (id < 0 || id >= MAX_SYSCALLS) {
        return 0;
    }

    // Retrieve the mount namespace
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (mntns == 0) {
        return 0;
    }

    // Update the syscalls
    unsigned char * syscall_value = lookup_or_init(&syscalls, mntns);
    if (syscall_value) {
        syscall_value[id] = 0x01;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Update the command name if required
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&comms, &comm) == NULL) {
        bpf_map_update_elem(&comms, &pid, &comm, BPF_ANY);
    }

    // Update the PIDs and send a new event for new PIDs
    if (bpf_map_lookup_elem(&pids, &pid) == NULL) {
        // New element, throw event
        u32 * event = bpf_ringbuf_reserve(&events, sizeof(u32), 0);
        if (!event) {
            // Not enough space within the ringbuffer
            return 0;
        }
        *event = pid;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_update_elem(&pids, &pid, &mntns, BPF_ANY);

    return 0;
}
