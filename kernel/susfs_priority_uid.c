// SPDX-License-Identifier: GPL-2.0
/*
 * SUSFS 2.4 priority UID filter (LKM port, stage 1: data + control node).
 *
 * Upstream (susfs4ksu v2.4.0, kernel/sys.c) skips the target UID in
 * getpriority()/setpriority() when the caller is an app and the target UID is in
 * the filter bitmap, so apps cannot enumerate other apps through getpriority().
 *
 * Stage 1 keeps the bitmap and the /proc node; the syscall hook that consumes
 * susfs_is_priority_uid_filtered() lands in stage 2.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/resource.h>

#define SUSFS_UID_FILTER_MIN   10000
#define SUSFS_UID_FILTER_MAX   19999
#define SUSFS_UID_FILTER_BITS  (SUSFS_UID_FILTER_MAX - SUSFS_UID_FILTER_MIN + 1)
#define SUSFS_UID_FILTER_WORDS BITS_TO_LONGS(SUSFS_UID_FILTER_BITS)
#define SUSFS_UID_APPS_MAX     4096

struct susfs_uid_filter {
	struct rcu_head rcu;
	unsigned long bits[SUSFS_UID_FILTER_WORDS];
};

static struct susfs_uid_filter __rcu *susfs_uid_bitmap;
static DEFINE_MUTEX(susfs_uid_mutex);
static char *susfs_uid_apps;
static struct proc_dir_entry *susfs_uid_entry;

static int susfs_uid_resolve(const char *pkg, unsigned int *uid)
{
	char path[300];
	struct path p;
	struct inode *inode;
	int n;

	n = snprintf(path, sizeof(path), "/data/data/%s", pkg);
	if (n <= 0 || n >= (int)sizeof(path))
		return -ENAMETOOLONG;

	if (kern_path(path, LOOKUP_FOLLOW, &p))
		return -ENOENT;

	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}

	*uid = from_kuid(&init_user_ns, inode->i_uid);
	path_put(&p);
	return 0;
}

bool susfs_is_priority_uid_filtered(unsigned int uid)
{
	struct susfs_uid_filter *b;
	bool hit = false;

	if (uid < SUSFS_UID_FILTER_MIN || uid > SUSFS_UID_FILTER_MAX)
		return false;

	rcu_read_lock();
	b = rcu_dereference(susfs_uid_bitmap);
	if (b)
		hit = test_bit(uid - SUSFS_UID_FILTER_MIN, b->bits);
	rcu_read_unlock();

	return hit;
}

static int susfs_uid_build(const char *apps, struct susfs_uid_filter *b)
{
	char *buf, *tok;
	int added = 0;

	buf = kstrdup(apps, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (tok = strsep(&buf, " \t\n,;"); tok;
	     tok = strsep(&buf, " \t\n,;")) {
		unsigned int uid;

		if (!*tok)
			continue;
		if (susfs_uid_resolve(tok, &uid))
			continue;
		if (uid < SUSFS_UID_FILTER_MIN || uid > SUSFS_UID_FILTER_MAX)
			continue;

		set_bit(uid - SUSFS_UID_FILTER_MIN, b->bits);
		added++;
	}

	kfree(buf);
	return added;
}

static ssize_t susfs_uid_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct susfs_uid_filter *b, *old;
	char *apps;
	ssize_t ret;

	if (count == 0)
		return 0;
	if (count > SUSFS_UID_APPS_MAX)
		return -EINVAL;

	apps = kzalloc(count + 1, GFP_KERNEL);
	if (!apps)
		return -ENOMEM;
	if (copy_from_user(apps, ubuf, count)) {
		kfree(apps);
		return -EFAULT;
	}

	if (!*apps) {
		/* empty write clears the filter */
		mutex_lock(&susfs_uid_mutex);
		old = rcu_dereference_protected(susfs_uid_bitmap,
						lockdep_is_held(&susfs_uid_mutex));
		rcu_assign_pointer(susfs_uid_bitmap, NULL);
		kfree(susfs_uid_apps);
		susfs_uid_apps = NULL;
		mutex_unlock(&susfs_uid_mutex);
		synchronize_rcu();
		if (old)
			kfree_rcu(old, rcu);
		ret = count;
		goto out;
	}

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b) {
		ret = -ENOMEM;
		goto out;
	}
	if (susfs_uid_build(apps, b) < 0) {
		kfree(b);
		ret = -ENOMEM;
		goto out;
	}

	mutex_lock(&susfs_uid_mutex);
	old = rcu_dereference_protected(susfs_uid_bitmap,
					lockdep_is_held(&susfs_uid_mutex));
	rcu_assign_pointer(susfs_uid_bitmap, b);
	kfree(susfs_uid_apps);
	susfs_uid_apps = apps;
	apps = NULL;
	mutex_unlock(&susfs_uid_mutex);
	synchronize_rcu();
	if (old)
		kfree_rcu(old, rcu);
	ret = count;

out:
	kfree(apps);
	return ret;
}

static int susfs_uid_show(struct seq_file *m, void *v)
{
	struct susfs_uid_filter *b;

	seq_printf(m, "susfs priority uid filter (lkm)\n");
	mutex_lock(&susfs_uid_mutex);
	seq_printf(m, "apps: %s\n", susfs_uid_apps ? susfs_uid_apps : "");
	mutex_unlock(&susfs_uid_mutex);

	rcu_read_lock();
	b = rcu_dereference(susfs_uid_bitmap);
	if (b) {
		unsigned int uid, n = 0;

		seq_printf(m, "uids:");
		for (uid = SUSFS_UID_FILTER_MIN; uid <= SUSFS_UID_FILTER_MAX; uid++) {
			if (test_bit(uid - SUSFS_UID_FILTER_MIN, b->bits)) {
				seq_printf(m, " %u", uid);
				n++;
			}
		}
		seq_printf(m, "\ncount: %u\n", n);
	} else {
		seq_printf(m, "uids: (none)\ncount: 0\n");
	}
	rcu_read_unlock();
	return 0;
}

static int susfs_uid_open(struct inode *inode, struct file *file)
{
	return single_open(file, susfs_uid_show, NULL);
}

static const struct proc_ops susfs_uid_ops = {
	.proc_open	= susfs_uid_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= susfs_uid_write,
};

/* ---- getpriority interception (stage 2) ---------------------------------
 *
 * Upstream v2.4 patches kernel/sys.c and skips the lookup with -ESRCH before
 * the target task is inspected. A module cannot edit that source, so the same
 * visibility change is produced at the syscall boundary: the target UID is
 * checked on entry and the return value is overwritten with -ESRCH on exit.
 * The syscall itself still runs, which is harmless for getpriority (it has no
 * side effects), and apps never see a value for a filtered UID.
 */
struct prio_probe_data {
	bool filtered;
};

static int prio_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prio_probe_data *d = (void *)ri->data;
	unsigned int target = 0;
	int which = (int)regs->regs[0];
	int who = (int)regs->regs[1];
	struct task_struct *task;

	d->filtered = false;

	if (from_kuid(&init_user_ns, current_cred()->uid) < SUSFS_UID_FILTER_MIN)
		return 0;
	if (who <= 0)
		return 0;

	switch (which) {
	case PRIO_PROCESS:
		rcu_read_lock();
		task = find_task_by_vpid(who);
		if (task)
			target = from_kuid(&init_user_ns, task_uid(task));
		rcu_read_unlock();
		break;
	case PRIO_USER:
		target = (unsigned int)who;
		break;
	default:
		return 0;
	}

	if (target && susfs_is_priority_uid_filtered(target))
		d->filtered = true;

	return 0;
}

static int prio_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prio_probe_data *d = (void *)ri->data;

	if (d->filtered) {
		regs_set_return_value(regs, -ESRCH);
		pr_info_ratelimited("susfs_priority_uid: hid a getpriority target\n");
	}
	return 0;
}

static struct kretprobe susfs_prio_krp = {
	.kp = {
		.symbol_name = "__arm64_sys_getpriority",
	},
	.entry_handler = prio_entry,
	.handler = prio_ret,
	.data_size = sizeof(struct prio_probe_data),
	.maxactive = 64,
};

int susfs_priority_uid_init(void)
{
	susfs_uid_entry = proc_create("susfs_priority_uid_filter", 0600, NULL,
				      &susfs_uid_ops);
	if (!susfs_uid_entry)
		pr_warn("susfs_priority_uid: control node unavailable\n");

	if (register_kretprobe(&susfs_prio_krp)) {
		pr_warn("susfs_priority_uid: getpriority probe unavailable, filter inactive\n");
	} else {
		pr_info("susfs_priority_uid: getpriority probe armed\n");
	}
	return 0;
}

void susfs_priority_uid_exit(void)
{
	struct susfs_uid_filter *old;

	unregister_kretprobe(&susfs_prio_krp);

	if (susfs_uid_entry) {
		proc_remove(susfs_uid_entry);
		susfs_uid_entry = NULL;
	}

	mutex_lock(&susfs_uid_mutex);
	old = rcu_dereference_protected(susfs_uid_bitmap,
					lockdep_is_held(&susfs_uid_mutex));
	rcu_assign_pointer(susfs_uid_bitmap, NULL);
	kfree(susfs_uid_apps);
	susfs_uid_apps = NULL;
	mutex_unlock(&susfs_uid_mutex);
	synchronize_rcu();
	kfree(old);
}