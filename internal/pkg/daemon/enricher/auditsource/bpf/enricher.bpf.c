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

SEC("kprobe/aa_audit")
int BPF_KPROBE(kprobe__aa_audit, int type, struct aa_profile * profile,
               struct apparmor_audit_data * ad)
{
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
    struct task_struct * task = (void *)bpf_get_current_task();
    const char * comm_ptr = BPF_CORE_READ(task, comm);

    char op[16];
    long op_len = read_kernel_str(op, sizeof(op), op_ptr);

    char comm[TASK_COMM_LEN] = {};
    long comm_len = read_kernel_str(comm, sizeof(comm), comm_ptr);

    char name[256];
    long name_len = read_kernel_str(name, sizeof(name), name_ptr);

    struct bpf_dynptr event;
    u32 size = 4 + 4 + 4 + 1 + op_len + comm_len + name_len;
    bpf_ringbuf_reserve_dynptr(&audit_log, size, 0, &event);
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
