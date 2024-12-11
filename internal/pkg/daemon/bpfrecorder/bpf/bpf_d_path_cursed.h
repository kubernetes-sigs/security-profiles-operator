#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
// A cursed reimplementation of bpf_d_path for use in hooks where bpf_d_path
// is unavailable.
// This implementation is cursed in the sense that changes to it will break the
// ebpf verifier in unexpected ways. When working on this, re-run spoc
// frequently to make sure the verifier remains happy. It can be extremely hard
// to figure out what particular change caused a verifier issue and how to fix
// it.
//
// TODO: Use loop helpers (https://docs.ebpf.io/linux/concepts/loops/)
// if verifier starts to spit out complexity errors.
// For now we wait until the numeric open coded iterators are widely available.

#define MAX_PATH_COMPONENTS 15

static __always_inline int bpf_d_path_cursed(struct path* path, char* buf, size_t sz)
{
    struct dentry* dentry = path->dentry;
    struct mount* mnt = container_of(path->mnt, struct mount, mnt);

    const unsigned char * names[MAX_PATH_COMPONENTS] = {};
    u8 lens[MAX_PATH_COMPONENTS] = {};

    // Walk to the top of the filesystem and store all components in the array.
    int component = 0;
    for(int j = 0; j < MAX_PATH_COMPONENTS; j++) {
        struct dentry *dentry_parent = BPF_CORE_READ(dentry, d_parent);

        if(dentry == dentry_parent) {
            // We've reached the top of this filesystem...
            struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
            if (mnt == mnt_parent) {
              // ...and this filesystem is the root filesystem. We're done!
              break;
            }
            // ...so we traverse one filesystem up.
            dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
            mnt = mnt_parent;
            // No need to add this to `names` as it is just "/".
        } else {
            // Add to names and traverse one directory up.
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            if(d_name.len >= 256) {
              bpf_printk("bpf_d_path_cursed: cannot handle directory length > 256");
              return -1;
            }
            names[component] = d_name.name;
            lens[component] = d_name.len;
            dentry = dentry_parent;
            component++;
        }
    }

    // Marking this as volatile prevents the C compiler from optimizing away
    // bounds checks that the eBPF verifier insists on.
    volatile u32 offset = 0;

    // We now walk the array in reverse order to construct a path string.
    while(component > 0) {
        component--;
        if(offset > sz - 256) {
          bpf_printk("bpf_d_path_cursed: cannot handle path length close to MAX_PATH");
          return -1;
        }
        // Add slash
        buf[offset] = '/';
        offset += 1;
        // Add component
        u8 len = lens[component];
        bpf_core_read(buf + offset, len, names[component]);
        offset += len;
    }
    return offset + 1;
}


// Create a struct path for a given dentry by combining it with the mount point
// of its parent path. Note that the returned path does not work with the
// kernel's bpf_d_path, as it does not like stack pointers.
static __always_inline struct path make_path(struct dentry *dentry, struct path *path) {
  struct path ret = {
      .mnt = BPF_CORE_READ(path, mnt),
      .dentry = dentry,
  };
  return ret;
}
