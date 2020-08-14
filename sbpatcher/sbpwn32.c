/*
 * sbpathcer32 - sandbox patcher for ios 9/10 (bootloader-base jailbreak)
 * iOS 9.0 - 10.3.3
 * Copyright (c) 2019 dora2ios
 *
 * Requires: tfp0 and bootrom/iboot exploit
 * Supports: iOS 9.0 - 10.3.3 (armv7 only)
 *
 * BUILD
 *
 * xcrun -sdk iphoneos clang sbpwn32.c patchfinder.o -arch armv7 -framework CoreFoundation -o rtbuddyd && strip rtbuddyd && codesign -f -s - -i com.apple.rtbuddyd --entitlements tfp0.plist rtbuddyd
 *
 */

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "patchfinder.h"
#include "mac_policy.h"

#define DEFAULT_KERNEL_SLIDE    0x80000000
#define KERNEL_BASE_ADDR        0x80001000
#define KDUMP_SIZE              0x1200000
#define CHUNK_SIZE              0x800

mach_port_t tfp0=0;
uint8_t kdump[KDUMP_SIZE] = {0};
uint32_t kernbase;
/* -- yalu102 by qwertyoruiop -- */
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t ReadAnywhere32(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t WriteAnywhere32(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

/* -- end -- */

mach_port_t get_kernel_task() {
    task_t kernel_task;
    if (KERN_SUCCESS != task_for_pid(mach_task_self(), 0, &kernel_task)) {
        return -1;
    }
    return kernel_task;
}

vm_address_t get_kernel_base() {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    while (1) {
        if (KERN_SUCCESS != vm_region_recurse_64(tfp0, &addr, &size, &depth, (vm_region_info_t) & info, &info_count))
            break;
        if (size > 1024 * 1024 * 1024) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MH_MAGIC) {
                addr -= 0x200000;
                vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MH_MAGIC) {
                    break;
                }
            }
            vm_address_t kbase = addr + 0x1000;
            return kbase;
        }
        addr += size;
    }
    return -1;
}

void dump_kernel(vm_address_t kernel_base, uint8_t *dest) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + KDUMP_SIZE; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

int main(int argc, char *argv[]) {
    
    printf("\nsbpwn32 v1.2\n");
    // tfp0
    tfp0 = get_kernel_task();
    if (!tfp0) {
        printf("failed task_for_pid(0)!\n");
        return -1;
    }
    printf("tfp0: 0x%08x\n", tfp0);
    
    // kernbase
    kernbase = get_kernel_base();
    if (!kernbase) {
        printf("failed search kernel base!\n");
        return -1;
    }
    printf("kbase: 0x%08x\n", kernbase);
    printf("kslide: 0x%08x\n", kernbase - KERNEL_BASE_ADDR);
    
    // kerneldump
    dump_kernel(kernbase, kdump);
    if (!(*(uint32_t*)&kdump[0] == MH_MAGIC)) {
        printf("failed read kernel memory!\n");
        return -1;
    }
    
    // sandbox
    
    uint32_t sbops = find_sbops(kernbase, kdump, KDUMP_SIZE);
    if (!sbops) {
        return -1;
    }
    
    printf("sbops: 0x%08x\n", sbops);
    printf("patching kernel\n");
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_mount_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_setauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_getauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_fork), 0);
    
    /* remount rootfs */
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    printf("mount? %d\n",mntr);
    
    int f = open("/.jbd/.installed_sakura", O_RDONLY);
    if(f == -1){
        printf("detected first boot time\n");
        open("/.jbd/.installed_sakura", O_RDWR|O_CREAT);
        open("/.cydia_no_stash",O_RDWR|O_CREAT);
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
    }
    
    printf("well done?!\n");
    return 0;
}
