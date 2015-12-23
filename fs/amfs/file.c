/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include "amfsctl.h"
#include "amfs_h_list.h"

struct amfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	struct dentry *dentry;
};

extern struct amfs_pattern_info *amfs_h_list[96];
extern int amfs_count_pattern_data_len(void);
extern int amfs_add_new_pattern(const char *pattern);
extern int amfs_remove_pattern(struct file *file, const char *pattern);
extern int amfs_check_file(struct dentry *dentry);
extern int amfs_check_if_bad(const char *u_buf, int buf_len);

static ssize_t amfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err = -EINVAL;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	/* can not perform 'cat' operation on pattern.db */
	/* user can list the data using ./amfsctl -l */
	err = amfs_check_file(dentry);
	if (err == 1) {
		pr_err("amfs_read: cat not permitted! "
					"use ioctl to list patterns!\n");
		err = -EPERM;
		goto out;
	}

	lower_file = amfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	if (err > 0) {
		int status = 0;
		int rc = 0;
		int is_bad_set = 0;
		int is_rc_set = 0;
		int is_bad = 0;
		struct amfs_sb_info *spd = NULL;

		spd = AMFS_SB(dentry->d_sb);
		if (!spd) {
			pr_err("amfs_read: Invalid amfs_sb_info!\n");
			err = -EINVAL;
			goto out;
		}

		/* Check and block read option if file contains malware pattern */
		/* allow otherwise */
		is_bad_set = file->f_inode->i_op->getxattr(dentry,
						AMFS_FILE_STATUS,
						(void *)&status, sizeof(int));
		is_rc_set = file->f_inode->i_op->getxattr(dentry, AMFS_REMOVE_COUNT,
							(void *)&rc, sizeof(int));
		if (is_bad_set > 0 && is_rc_set > 0 && status == AMFS_BAD_VAL) {
			/* bad and rc attributes are set hence this was a bad file */
			/* check if remove count matches, */
			/* if yes then it is still a bad file and scan is not required */
			/* otherwise, some patterns has been removed from pattern.db */
			/* prev bad file might be good not. Need to scan again! */
			if (rc == spd->pattern_db_rc) {
				/* rc matches, still a bad file, scan not req */
				err = -EPERM;
				goto out;
			} else {
				is_bad = amfs_check_if_bad(buf, err);
				if (is_bad == 1) {
					/* still a bad file. Just update rc & return ERERM */
					if (file->f_inode->i_op->setxattr(dentry,
								AMFS_REMOVE_COUNT,
								(void *)&(spd->pattern_db_rc),
								sizeof(int), 0)) {
						pr_err("amfs_read: remove count update "
								"failed for pattern.db\n");
					}
					err = -EPERM;
					goto out;
				} else {
					/* File is good now. Remove attr! */
					if (file->f_inode->i_op->removexattr(dentry,
								AMFS_FILE_STATUS)) {
						pr_err("amfs_read: remove AMFS_FILE_STATUS "
								"failed for pattern.db\n");
					}
					if (file->f_inode->i_op->removexattr(dentry,
								AMFS_REMOVE_COUNT)) {
						pr_err("amfs_read: remove AMFS_REMOVE_COUNT "
								"failed for pattern.db\n");
					}
				}
			}
		} else {
			/* bad and rc attributes does not exists! Need to scan! */
			/* It was either a new file or a good file */
			is_bad = amfs_check_if_bad(buf, err);
			if (is_bad == 1) {
				/* File is bad now. add all attributes & return ERERM */
				status = AMFS_BAD_VAL;
				is_bad_set = file->f_inode->i_op->setxattr(dentry,
								AMFS_FILE_STATUS,
								(void *)&status,
								sizeof(int), 0);
				is_rc_set = file->f_inode->i_op->setxattr(dentry,
								AMFS_REMOVE_COUNT,
								(void *)&(spd->pattern_db_rc),
								sizeof(int), 0);
				if (is_bad_set || is_rc_set) {
					pr_err("amfs_read: setxattr failed for bad file!"
							 "is_bad_set(%d) is_rc_set(%d)\n",
							 is_bad_set, is_rc_set);
				}
				err = -EPERM;
				goto out;
			}
		}
	}

	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));

out:
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = -EINVAL;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = amfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	if (err > 0) {
		int status = 0;
		int rc = 0;
		int is_bad_set = 0;
		int is_rc_set = 0;
		int is_bad = 0;

		/* Check if file contains malware pattern */
		/* if yes, then set respective attributes */
		is_bad_set = file->f_inode->i_op->getxattr(dentry, AMFS_FILE_STATUS,
							(void *)&status, sizeof(int));
		is_rc_set = file->f_inode->i_op->getxattr(dentry, AMFS_REMOVE_COUNT,
							(void *)&rc, sizeof(int));
		if (is_bad_set < 0 || is_rc_set < 0) {
			/* attributes does not exists! Need to scan! */
			is_bad = amfs_check_if_bad(buf, err);
			if (is_bad == 1) {
				/* File is bad now. add all attributes! */
				struct amfs_sb_info *spd = NULL;

				spd = AMFS_SB(dentry->d_sb);
				if (!spd) {
					pr_err("amfs_write: Invalid amfs_sb_info!\n");
					goto out;
				}

				status = AMFS_BAD_VAL;
				is_bad_set = file->f_inode->i_op->setxattr(dentry,
								AMFS_FILE_STATUS,
								(void *)&status,
								sizeof(int), 0);
				is_rc_set = file->f_inode->i_op->setxattr(dentry,
							AMFS_REMOVE_COUNT,
							(void *)&(spd->pattern_db_rc),
							sizeof(int), 0);
				if (is_bad_set || is_rc_set) {
					pr_err("amfs_write: setxattr failed for bad file!"
						 "is_bad_set(%d) is_rc_set(%d)\n",
						 is_bad_set, is_rc_set);
				}
			}
		}
	}

out:
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}
	return err;
}

/**
 * amfs_filldir
 * a callback function which will be called from readdir
 * @ctx: context of directory being looked up
 * @lower_name: file name present in lower fs
 * @lower_namelen: length of lower filename
 * @ino: inode number of lower file
 * @d_type: type of the file
 *
 * hide operation for bad file is being performed here
 * if successful, then file will not be listed via 'ls'
 */
static int amfs_filldir(struct dir_context *ctx, const char *lower_name,
			int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	int err;
	struct dentry *c_dentry;
	struct qstr curr_name;
	struct amfs_getdents_callback *cb_buf =
				container_of(ctx, struct amfs_getdents_callback, ctx);

	curr_name.name = lower_name;
	curr_name.len = lower_namelen;
	curr_name.hash = full_name_hash (lower_name, lower_namelen);

	c_dentry = d_lookup(cb_buf->dentry, &curr_name);

	if (c_dentry) {
		int status = 0;
		int rc = 0;
		int is_bad_set = 0;
		int is_rc_set = 0;

		/* Check if attributes are set */
		/* if yes, then hide the file while listing */
		is_bad_set = c_dentry->d_inode->i_op->getxattr(c_dentry,
							AMFS_FILE_STATUS,
							(void *)&status,
							sizeof(int));
		is_rc_set = c_dentry->d_inode->i_op->getxattr(c_dentry,
							AMFS_REMOVE_COUNT,
							(void *)&rc, sizeof(int));
		if (is_bad_set > 0 && is_rc_set > 0 && status == AMFS_BAD_VAL) {
			err = 0;
			goto out;
		}
	}

	cb_buf->caller->pos = cb_buf->ctx.pos;
	err = !dir_emit(cb_buf->caller, lower_name, lower_namelen, ino, d_type);

out:
	return err;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err = -EINVAL;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct amfs_getdents_callback cb_buf = {
		.ctx.actor = amfs_filldir,
		.caller = ctx,
	};

	lower_file = amfs_lower_file(file);
	cb_buf.dentry = lower_file->f_path.dentry;

	lower_file->f_pos = ctx->pos;
	err = iterate_dir(lower_file, &cb_buf.ctx);
	ctx->pos = cb_buf.ctx.pos;

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
	return err;
}

static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	int err = -EINVAL;
	struct file *lower_file;

	switch (cmd) {
	case AMFSCTL_CNT_PATTERNS:
		{
			int len = amfs_count_pattern_data_len();
			err = put_user(len, (int *)arg);
			if (err) {
				pr_err("amfs_unlocked_ioctl: put_user failed!\n");
				err = -EFAULT;
				goto out;
			}
		}
		break;
	case AMFSCTL_LST_PATTERNS:
		{
			int i = 0;
			struct amfs_pattern_info *temp = NULL;
			struct amfsctl_arg_s *p_k_arg = NULL;
			struct amfsctl_arg_s *p_u_arg = NULL;

			p_u_arg = (struct amfsctl_arg_s *) arg;

			p_k_arg = kmalloc(sizeof(struct amfsctl_arg_s),
								__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
								"p_k_arg!\n");
				err = -ENOMEM;
				goto out;
			}
			if (copy_from_user(p_k_arg, p_u_arg,
							sizeof(struct amfsctl_arg_s))) {
				pr_err("amfs_unlocked_ioctl: copy_from_user "
								"failed for p_k_arg!\n");
				err = -EFAULT;
				goto out_list_patterns;
			}

			p_k_arg->pattern_str = kmalloc((p_u_arg->pattern_len + 1),
								__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg->pattern_str) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
							"p_k_arg->pattern_str!\n");
				err = -ENOMEM;
				goto out_list_patterns;
			}

			for (i = 0; i < 96; i++) {
				if (amfs_h_list[i]) {
					temp = amfs_h_list[i];

					while (temp) {
						if (temp->str) {
							strcat(p_k_arg->pattern_str,
									temp->str);
							strcat(p_k_arg->pattern_str,
									"\n");
						}
						temp = temp->next;
					}
				}
			}

			err = copy_to_user(p_u_arg->pattern_str, p_k_arg->pattern_str,
							(p_u_arg->pattern_len + 1));
			if (err) {
				pr_err("amfs_unlocked_ioctl: copy_to_user failed "
								"while listing!\n");
				err = -EFAULT;
				goto out_list_patterns;
			}

out_list_patterns:
			if (p_k_arg->pattern_str)
				kfree(p_k_arg->pattern_str);
			if (p_k_arg)
				kfree(p_k_arg);
			goto out;
		}
		break;
	case AMFSCTL_ADD_PATTERNS:
		{
			struct amfsctl_arg_s *p_k_arg = NULL;
			struct amfsctl_arg_s *p_u_arg = NULL;

			p_u_arg = (struct amfsctl_arg_s *)arg;

			p_k_arg = kmalloc(sizeof(struct amfsctl_arg_s),
								__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
								"p_k_arg!\n");
				err = -ENOMEM;
				goto out;
			}
			if (copy_from_user(p_k_arg, p_u_arg,
							sizeof(struct amfsctl_arg_s))) {
				pr_err("amfs_unlocked_ioctl: copy_from_user failed "
								"for p_k_arg!\n");
				err = -EFAULT;
				goto out_add_patterns;
			}

			p_k_arg->pattern_str = kmalloc(p_u_arg->pattern_len,
								__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg->pattern_str) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
							"p_k_arg->pattern_str!\n");
				err = -ENOMEM;
				goto out_add_patterns;
			}
			if (copy_from_user(p_k_arg->pattern_str, p_u_arg->pattern_str,
								p_u_arg->pattern_len)) {
				pr_err("amfs_unlocked_ioctl: copy_from_user failed "
							"for elements of p_k_arg!\n");
				err = -EFAULT;
				goto out_add_patterns;
			}

			err = amfs_add_new_pattern(p_k_arg->pattern_str);
			if (err)
				pr_err("amfs_unlocked_ioctl: err(%d)\n", err);

out_add_patterns:
			if (p_k_arg->pattern_str)
				kfree(p_k_arg->pattern_str);
			if (p_k_arg)
				kfree(p_k_arg);
			goto out;
		}
		break;
	case AMFSCTL_REM_PATTERNS:
		{
			struct amfsctl_arg_s *p_k_arg = NULL;
			struct amfsctl_arg_s *p_u_arg = NULL;

			p_u_arg = (struct amfsctl_arg_s *)arg;

			p_k_arg = kmalloc(sizeof(struct amfsctl_arg_s),
							__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
								"p_k_arg!\n");
				err = -ENOMEM;
				goto out;
			}
			if (copy_from_user(p_k_arg, p_u_arg,
							sizeof(struct amfsctl_arg_s))) {
				pr_err("amfs_unlocked_ioctl: copy_from_user failed "
								"for p_k_arg!\n");
				err = -EFAULT;
				goto out_rem_patterns;
			}

			p_k_arg->pattern_str = kmalloc(p_u_arg->pattern_len,
							__GFP_ZERO|GFP_KERNEL);
			if (!p_k_arg->pattern_str) {
				pr_err("amfs_unlocked_ioctl: kmalloc failed for "
							"p_k_arg->pattern_str!\n");
				err = -ENOMEM;
				goto out_rem_patterns;
			}
			if (copy_from_user(p_k_arg->pattern_str, p_u_arg->pattern_str,
								p_u_arg->pattern_len)) {
				pr_err("amfs_unlocked_ioctl: copy_from_user failed "
							"for elements of p_k_arg!\n");
				err = -EFAULT;
				goto out_rem_patterns;
			}

			err = amfs_remove_pattern(file, p_k_arg->pattern_str);
			if (err)
				pr_err("amfs_remove_pattern: err(%d)\n", err);

out_rem_patterns:
			if (p_k_arg->pattern_str)
				kfree(p_k_arg->pattern_str);
			if (p_k_arg)
				kfree(p_k_arg);
			goto out;
		}
		break;
	default:
		{
			lower_file = amfs_lower_file(file);

			/* XXX: use vfs_ioctl if/when VFS exports it */
			if (!lower_file || !lower_file->f_op)
				goto out;
			if (lower_file->f_op->unlocked_ioctl)
				err = lower_file->f_op->unlocked_ioctl(lower_file,
									cmd, arg);

			/* some ioctls can change inode attributes(EXT2_IOC_SETFLAGS) */
			if (!err)
				fsstack_copy_attr_all(file_inode(file),
							  file_inode(lower_file));
		}
		break;
	}

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		pr_err("amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			pr_err("amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * Amfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Amfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * Amfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};
