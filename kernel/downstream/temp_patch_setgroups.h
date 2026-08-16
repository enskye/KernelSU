// SPDX-License-Identifier: GPL-2.0-only
/*
 * Strip AID_READPROC (gid 3009) from setgroups() to prevent isolated
 * processes from bypassing hidepid=2 and reading other processes'
 * mountinfo.
 *
 * Adapted from backslashxx/KernelSU@9f01a3d for this tree's
 * ksu_syscall_table_hook()/ksu_syscall_table_unhook() API.
 */
#ifndef __KSU_H_TEMP_PATCH_SETGROUPS
#define __KSU_H_TEMP_PATCH_SETGROUPS

#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

#include "../hook/syscall_hook.h"

#define KSU_AID_READPROC 3009

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 65536
#endif

/*
 * ARM64: syscall args in pt_regs->regs[0..7]
 * ARM32: syscall args in pt_regs->ARM_r0..r6
 * x86_64: syscall args in pt_regs->di, si, dx, r10, r8, r9
 */
#if defined(CONFIG_ARM64)
#define KSU_SYSCALL_ARG1(r) ((r)->regs[0])
#define KSU_SYSCALL_ARG2(r) ((r)->regs[1])
#define KSU_SYSCALL_SET_ARG1(r, v) ((r)->regs[0] = (unsigned long)(v))
#elif defined(CONFIG_ARM)
#define KSU_SYSCALL_ARG1(r) ((r)->ARM_r0)
#define KSU_SYSCALL_ARG2(r) ((r)->ARM_r1)
#define KSU_SYSCALL_SET_ARG1(r, v) ((r)->ARM_r0 = (unsigned long)(v))
#elif defined(CONFIG_X86_64) || defined(CONFIG_X86)
#define KSU_SYSCALL_ARG1(r) ((r)->di)
#define KSU_SYSCALL_ARG2(r) ((r)->si)
#define KSU_SYSCALL_SET_ARG1(r, v) ((r)->di = (unsigned long)(v))
#else
#error "Unsupported architecture"
#endif

static void ksu_modify_setgroups(int *gidsetsize, gid_t __user *grouplist)
{
	int i = 0;
	int size = *gidsetsize;
	gid_t gid;
	gid_t last;

	if (size <= 0)
		return;

	if (size > NGROUPS_MAX)
		return;

	/* adbd legitimately needs readproc for shell debugging */
	if (!strcmp(current->comm, "adbd"))
		return;

	while (i < size) {
		if (get_user(gid, &grouplist[i]))
			return;

		if (gid != KSU_AID_READPROC) {
			i++;
			continue;
		}

		/*
		 * Swap-remove: supplementary gid order does not matter.
		 * Avoids needing memmove_user().
		 */
		if (i != size - 1) {
			if (get_user(last, &grouplist[size - 1]))
				return;
			if (put_user(last, &grouplist[i]))
				return;
		}

		size--;
		*gidsetsize = size;

		pr_info("ksu_setgroups: %s: %d: stripped gid %d\n",
			current->comm, current->pid, KSU_AID_READPROC);
	}
}

static long (*orig_sys_setgroups)(const struct pt_regs *regs);

static long ksu_sys_setgroups(const struct pt_regs *regs)
{
	struct pt_regs *uregs = (struct pt_regs *)regs;
	int gidsetsize = (int)KSU_SYSCALL_ARG1(uregs);
	gid_t __user *grouplist =
		(gid_t __user *)(unsigned long)KSU_SYSCALL_ARG2(uregs);

	ksu_modify_setgroups(&gidsetsize, grouplist);

	/* Write modified gidsetsize back into arg0 register */
	KSU_SYSCALL_SET_ARG1(uregs, gidsetsize);

	if (orig_sys_setgroups)
		return orig_sys_setgroups(regs);

	return -ENOSYS;
}

static void __init ksu_init_setgroups_patch(void)
{
	pr_info("ksu_setgroups: installing temporary setgroups patch\n");
	ksu_syscall_table_hook(__NR_setgroups, ksu_sys_setgroups,
			       &orig_sys_setgroups);
}

#endif /* __KSU_H_TEMP_PATCH_SETGROUPS */
