// clang-format off
#include <vmlinux.h>
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif

#define MAX_NAMESPACES 8096

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} audit_log SEC(".maps");

// Counts the events which did not fit into the ring buffer. The userspace sums
// the per CPU values and reports them.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} lost_events SEC(".maps");

static __always_inline u32 get_mntns()
{
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

static __always_inline long read_kernel_str(char * stack_ptr, u32 size,
                                            const char * kernel_ptr)
{
    long len = 0;
    if (kernel_ptr) {
        len = bpf_probe_read_kernel_str(stack_ptr, size, kernel_ptr);
    }
    if (len < 1) {
        stack_ptr[0] = 0;
        len = 1;
    }
    return len;
}

// get_audit_data returns the AppArmor audit data aa_audit got called with.
// Since Linux 6.7 it takes that data, which embeds the common LSM audit data.
// Before, it took the common data, which points to the AppArmor one.
static __always_inline struct apparmor_audit_data * get_audit_data(void * data)
{
    if (bpf_core_field_exists(struct apparmor_audit_data, common)) {
        return data;
    }
    return BPF_CORE_READ((struct common_audit_data *)data, apparmor_audit_data);
}

SEC("kprobe/aa_audit")
int BPF_KPROBE(kprobe__aa_audit, int type, struct aa_profile * profile,
               void * data)
{
    struct apparmor_audit_data * ad = get_audit_data(data);
    if (!ad) {
        return 0;
    }
    const int error = BPF_CORE_READ(ad, error);
    if (likely(!error)) {
        return 0;
    }
    if (type == AUDIT_APPARMOR_HINT || type == AUDIT_APPARMOR_STATUS) {
        return 0;
    }

    u32 mntns = get_mntns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 request = BPF_CORE_READ(ad, request);
    u8 complain = (BPF_CORE_READ(profile, mode) == APPARMOR_COMPLAIN);
    const char * name_ptr = BPF_CORE_READ(ad, name);
    const char * op_ptr = BPF_CORE_READ(ad, op);

    char op[16];
    long op_len = read_kernel_str(op, sizeof(op), op_ptr);

    // bpf_get_current_comm always terminates the name, the length includes
    // the terminator like the one of the other strings.
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    long comm_len = sizeof(comm);
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (comm[i] == 0) {
            comm_len = i + 1;
            break;
        }
    }

    char name[256];
    long name_len = read_kernel_str(name, sizeof(name), name_ptr);

    struct bpf_dynptr event;
    u32 size = 4 + 4 + 4 + 1 + op_len + comm_len + name_len;
    if (bpf_ringbuf_reserve_dynptr(&audit_log, size, 0, &event) != 0) {
        // The dynptr has to be released even if nothing got reserved.
        bpf_ringbuf_discard_dynptr(&event, 0);
        u32 zero = 0;
        u64 * lost = bpf_map_lookup_elem(&lost_events, &zero);
        if (lost) {
            *lost += 1;
        }
        return 0;
    }
    bpf_dynptr_write(&event, 0, &mntns, 4, 0);
    bpf_dynptr_write(&event, 4, &pid, 4, 0);
    bpf_dynptr_write(&event, 8, &request, 4, 0);
    bpf_dynptr_write(&event, 12, &complain, 1, 0);
    u32 offset = 13;
    bpf_dynptr_write(&event, offset, &op, op_len, 0);
    offset += op_len;
    bpf_dynptr_write(&event, offset, &comm, comm_len, 0);
    offset += comm_len;
    bpf_dynptr_write(&event, offset, &name, name_len, 0);
    offset += name_len;
    bpf_ringbuf_submit_dynptr(&event, 0);

    return 0;
}
