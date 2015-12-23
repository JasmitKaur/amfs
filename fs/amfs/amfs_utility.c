/*********************************************************************
 * FILE:	amfs_utility.c
 * AUTHOR:	jasmit kaur
 * LOGON ID:	110463904
 * DUE DATE:	11/8/2015
 *
 * PURPOSE:	contains utility methods
 *********************************************************************/

#include "amfs.h"
#include "amfs_h_list.h"

extern struct amfs_pattern_info *amfs_h_list[96];

/**
 * amfs_set_immutable_flag
 * to enable immutable flag of given file pointer
 * @fp: file pointer
 *
 * input is mandatory
 * returns 0 on success, otherwise negative error value
 */
int amfs_set_immutable_flag(struct file *fp)
{
	int err = -EINVAL;
	mm_segment_t oldfs;
	unsigned int flags;

	if (!fp) {
		pr_err("amfs_set_immutable_flag: Invalid file pointer!\n");
		goto out;
	}

	flags = FS_IMMUTABLE_FL;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = fp->f_op->unlocked_ioctl(fp, FS_IOC_SETFLAGS,
					(unsigned long) &flags);
	set_fs(oldfs);
	if (err) {
		pr_err("amfs_set_immutable_flag: unlocked_ioctl failed "
				"while setting immutable flag! err(%d)\n", err);
	}

out:
	return err;
}

/**
 * amfs_reset_immutable_flag
 * to disable immutable flag of given file pointer
 * @fp: file pointer
 *
 * input is mandatory
 * returns 0 on success, otherwise negative error value
 */
int amfs_reset_immutable_flag(struct file *fp)
{
	int err = -EINVAL;
	mm_segment_t oldfs;
	unsigned int old_flag;
	unsigned int new_flag;

	if (!fp) {
		pr_err("amfs_reset_immutable_flag: Invalid file pointer!\n");
		goto out;
	}

	new_flag = 0x000000FF & ~FS_IMMUTABLE_FL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = fp->f_op->unlocked_ioctl(fp, FS_IOC_GETFLAGS,
						(unsigned long) &old_flag);
	if (err) {
		pr_err("amfs_reset_immutable_flag: unlocked_ioctl failed "
				"while getting old_flag! err(%d)\n", err);
		goto out;
	}

	new_flag &= old_flag;

	err = fp->f_op->unlocked_ioctl(fp, FS_IOC_SETFLAGS,
						(unsigned long) &new_flag);
	set_fs(oldfs);
	if (err) {
		pr_err("amfs_reset_immutable_flag: unlocked_ioctl failed "
				"while setting new_flag! err(%d)\n", err);
	}

out:
	return err;
}

/**
 * amfs_db_rename - rename temp file with given output file name
 * @fp_tmp: file structure of temp file to be renamed
 * @fp_out: file structure of output file
 *
 * both input arguments are mandatory
 * returns 0 on success, otherwise negative error value.
 */
int amfs_db_rename(struct file *fp_tmp, struct file *fp_out)
{
	int err = -EINVAL;
	struct dentry *old_dentry = NULL;
	struct dentry *new_dentry = NULL;
	struct dentry *old_dir_dentry = NULL;
	struct dentry *new_dir_dentry = NULL;
	struct dentry *d_check = NULL;

	if (!fp_tmp || !fp_out) {
		pr_err("amfs_db_rename: Invalid file pointers for rename\n");
		goto out;
	}

	old_dentry = fp_tmp->f_path.dentry;
	new_dentry = fp_out->f_path.dentry;
	old_dir_dentry = dget_parent(old_dentry);
	new_dir_dentry = dget_parent(new_dentry);
	d_check = lock_rename(old_dir_dentry, new_dir_dentry);
	if (d_check == old_dentry) {
		pr_err("amfs_db_rename: source should not be ancestor of target\n");
		goto out_unlock;
	}
	if (d_check == new_dentry) {
		pr_err("amfs_db_rename: target should not be ancestor of source\n");
		err = -ENOTEMPTY;
		goto out_unlock;
	}

	err = vfs_rename(old_dir_dentry->d_inode,
					 old_dentry,
					 new_dir_dentry->d_inode,
					 new_dentry,
					 NULL, 0);
	if (err)
		pr_err("amfs_db_rename: vfs_rename failed! err (%d)\n", err);

out_unlock:
	unlock_rename(old_dir_dentry, new_dir_dentry);
out:
	return err;
}

/**
 * amfs_check_file
 * to check if given file is pattern db
 * @dentry: dentry of file to be checked
 *
 * input is mandatory
 * returns 1 if file is pattern db, otherwise negative error value
 */
int amfs_check_file(struct dentry *dentry)
{
	int err = -EINVAL;
	struct amfs_sb_info *spd = NULL;

	if (!dentry) {
		pr_err("amfs_check_file: Invalid input dentry!\n");
		goto out;
	}

	spd = AMFS_SB(dentry->d_sb);
	if (!spd) {
		pr_err("amfs_check_file: Invalid sb info!\n");
		goto out;
	}

	if (dentry->d_inode->i_ino == spd->ino) {
		/* file is pattern.db */
		err = 1;
	}

out:
	return err;
}

/**
 * amfs_is_mount_option_valid
 * to check if mount option is valid
 * @lower_path: lower device name
 * @raw_data: option string
 *
 * both inputs are mandatory
 * returns 0 if valid and raw_data will point to file path name,
 * otherwise negative error value
 */
char *amfs_is_mount_option_valid(char *lower_path, char *raw_data)
{
	int err = -EINVAL;
	int lower_end = 0;
	int file_start = 0;
	int pattern_db_path_len = 0;
	char *str = NULL;
	char *file_path = NULL;
	struct file *fp = NULL;

	if (!lower_path || !raw_data
		|| !strlen(lower_path) || !strlen(raw_data)) {
		pr_err("amfs_is_mount_option_valid: Mount option buffer "
						"is NULL!\n");
		goto out;
	}

	str = strrchr(raw_data, ',');
	if (str) {
		pr_err("amfs_is_mount_option_valid: Invalid mount option! "
				"Multiple options are not permitted!\n");
		goto out;
	}

	/* mount option should start with "pattdb=" */
	if (strncmp(raw_data, "pattdb=", 7)) {
		pr_err("amfs_is_mount_option_valid: Invalid option!\n");
		goto out;
	}

	str = strstr(raw_data, "pattdb=");
	str += strlen("pattdb=");

	/* check if db filename is given after string "pattdb=" */
	if (!str || !strlen(str)) {
		pr_err("amfs_is_mount_option_valid: Invalid db filename!\n");
		goto out;
	}

	/* there is a possibility that slash need to be added */
	/* hence +2 while kmalloc */
	pattern_db_path_len = strlen(lower_path) + strlen(str) + 2;
	file_path = kmalloc(pattern_db_path_len,
							__GFP_ZERO|GFP_KERNEL);
	if (!file_path) {
		pr_err("amfs_is_mount_option_valid: kmalloc failed for "
						"file_path!\n");
		err = -ENOMEM;
		goto out;
	}

	/* lower path is ready to be copied */
	strncpy(file_path, lower_path, strlen(lower_path));

	lower_end = strncmp((lower_path + strlen(lower_path) - 1), "/", 1);
	file_start = strncmp(str, "/", 1);
	if (!lower_end && !file_start) {
		/* Both, device path & file path has slash! remove one slash! */
		str++;
	} else if (lower_end && file_start) {
		/* device path & file path doesn't have slash! add one slash! */
		strcat(file_path, "/");
	}

	strcat(file_path, str);

	/* open pattern file */
    fp = filp_open(file_path, O_RDONLY, 0);
    if (!fp || IS_ERR(fp)) {
		pr_err("amfs_is_mount_option_valid: filp_open err %d\n",
						(int) PTR_ERR(fp));
		err = (int) PTR_ERR(fp);
		goto out;
    }

	/* check if input file has read permission */
	/* if not then return error */
	if (!fp->f_op->read) {
		err = -EPERM;
		pr_err("amfs_is_mount_option_valid: Read operation not permitted!\n");
		goto out_fp;
	}

out_fp:
	if (fp && !IS_ERR(fp))
		filp_close(fp, NULL);
	return file_path;
out:
	return ERR_PTR(err);
}

/**
 * amfs_check_if_bad
 * to check if given buffer contains malware patterns
 * @u_buf: user buffer
 * @buf_len: length of buffer
 *
 * both inputs are mandatory
 * returns 1 if malware patter is found, otherwise negative error value
 */
int amfs_check_if_bad(const char *u_buf, int buf_len)
{
	int err = -EINVAL;
	int i = 0;
	char *k_buf = NULL;
	struct amfs_pattern_info *temp = NULL;

	if (!u_buf || (buf_len <= 0)) {
		pr_err("amfs_check_if_bad: Invalid input!\n");
		goto out;
	}

	k_buf = kmalloc(buf_len, __GFP_ZERO|GFP_KERNEL);
	if (!k_buf) {
		pr_err("amfs_check_if_bad: kmalloc failed for k_buf!\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user(k_buf, u_buf, buf_len)) {
		pr_err("amfs_check_if_bad: copy_from_user failed for "
						"k_buf!\n");
		err = -EFAULT;
		goto out;
	}

	for (i = 0; i < 96; i++) {
		if (amfs_h_list[i]) {
			temp = amfs_h_list[i];

			while (temp) {
				if (strstr(k_buf, temp->str)) {
					/* malware pattern found */
					err = 1;
					goto out;
				}
				temp = temp->next;
			}
		}
	}

out:
	if (k_buf)
		kfree(k_buf);
	return err;
}
