/*********************************************************************
* FILE:		amfs_h_list.c
* AUTHOR:	jasmit kaur
* LOGON ID:	110463904
* DUE DATE:	11/8/2015
*
* PURPOSE:	once amfs module is mounted, malware patterns specified
*		in pattern.db is being loaded in memory and is being
*		managd using hashed linked lists. This file includes
*		APIs to manage in-memory data structure.
*********************************************************************/

#include "amfs.h"
#include "amfs_h_list.h"

/* restricting max len of a malware pattern */
#define AMFSCTL_PATTERN_LEN_MAX	256

/* restricting buffer length with page size */
#define BUF_LEN_MAX	4096

/* Global hash list to store pointers to pattern lists */
/* Hash function = ASCII value of first char reduced by 32 */
struct amfs_pattern_info *amfs_h_list[96];

extern int amfs_set_immutable_flag(struct file *fp);
extern int amfs_reset_immutable_flag(struct file *fp);
extern int amfs_db_rename(struct file *fp_tmp, struct file *fp_out);

/**
 * amfs_add_new_pattern
 * to add new malware pattern in db
 * @pattern: new malware pattern to be added
 *
 * Input argument is mandatory.
 * Returns 0 on success, otherwise negative error value.
 */
int amfs_add_new_pattern(const char *pattern)
{
	int err = -EINVAL;
	struct amfs_pattern_info *new_node = NULL;
	struct amfs_pattern_info *temp = NULL;
	struct amfs_pattern_info *prev = NULL;
	int h_index = 0;
	int exists = 0;

	if (!pattern || !strlen(pattern)) {
		pr_err("amfs_add_new_pattern: Invalid input pattern!\n");
		goto out;
	}

	new_node = kmalloc(sizeof(struct amfs_pattern_info),
							__GFP_ZERO|GFP_KERNEL);
	if (!new_node) {
		pr_err("amfs_add_new_pattern: kmalloc failed for new_node\n");
		err = -ENOMEM;
		goto out;
	}

	new_node->str = kmalloc(strlen(pattern) + 1, __GFP_ZERO|GFP_KERNEL);
	if (!new_node->str) {
		pr_err("amfs_add_new_pattern: kmalloc failed for "
				"new_node->str!\n");
		err = -ENOMEM;
		goto out_free_node;
	}

	strlcpy(new_node->str, pattern, strlen(pattern) + 1);
	new_node->next = NULL;

	h_index = pattern[0]-32;

	if (amfs_h_list[h_index]) {
		/* traverse and check if it already exists */
		temp = amfs_h_list[h_index];
		prev = amfs_h_list[h_index];
		while (temp) {
			if (!strcmp(pattern, temp->str)) {
				pr_info("amfs_add_new_pattern: pattern already "
						"exists!\n");
				exists = 1;
				goto out_free_node;
			}
			prev = temp;
			temp = temp->next;
		}
		if (!exists && !temp) {
			/* insert new node at the end of linked list */
			prev->next = new_node;
			err = 0;
		}
	} else {
		/* insert new node at the begining of linked list */
		amfs_h_list[h_index] = new_node;
		err = 0;
	}

out:
	return err;
out_free_node:
	if (new_node->str)
		kfree(new_node->str);
	if (new_node)
		kfree(new_node);
	return err;
}

/**
 * amfs_remove_pattern
 * to remove existing malware pattern in db
 * @pattern: existing malware pattern to be removed
 *
 * Input argument is mandatory.
 * Returns 0 on success, otherwise negative error value.
 */
int amfs_remove_pattern(struct file *file, const char *pattern)
{
	int err = -EINVAL;
	struct amfs_pattern_info *prev = NULL;
	struct amfs_pattern_info *temp = NULL;
	struct amfs_sb_info *spd = NULL;
	int i = 0;

	if (!file || !pattern || !strlen(pattern)) {
		pr_err("amfs_remove_pattern: Invalid input!\n");
		goto out;
	}

	spd = AMFS_SB(file->f_inode->i_sb);
	if (!spd) {
		pr_err("amfs_remove_pattern: Invalid amfs_sb_info!\n");
		goto out;
	}

	i = pattern[0]-32;
	if (amfs_h_list[i]) {
		temp = amfs_h_list[i];

		while (temp) {
			/* look for match */
			if (!strcmp(pattern, temp->str)) {
				/* Match found */
				if (!prev) {
					amfs_h_list[i] = temp->next;
				} else {
					prev->next = temp->next;
				}
				/* increament remove count of patterns */
				spd->pattern_db_rc++;
				err = 0;
				goto out;
			}
			prev = temp;
			temp = temp->next;
		}
	}
	pr_info("amfs_remove_pattern: Pattern doesn't exist!\n");

out:
	if (!err && temp && temp->str) {
		kfree(temp->str);
		temp->str = NULL;
		kfree(temp);
		temp = NULL;
	}
	return err;
}

/**
 * amfs_count_pattern_data_len
 * to get total length of pattern db, including new_line char
 *
 * no input argument is required
 * returns the length of data
 */
int amfs_count_pattern_data_len(void)
{
	int i;
	int len = 0;
	struct amfs_pattern_info *temp = NULL;

	for (i = 0; i < 96; i++) {
		if (amfs_h_list[i]) {
			temp = amfs_h_list[i];

			while (temp) {
				len += strlen(temp->str) + 1;
				temp = temp->next;
			}
		}
	}

	return len;
}

/**
 * amfs_update_pattern_db
 * to update pattern.db file on disc while unmounting amfs
 * @spd: amfs superblock info containing path of db file
 *
 * input is mandatory
 * returns 0 on success, otherwise negative error value
 */
int amfs_update_pattern_db(struct amfs_sb_info *spd)
{
	int err = -EINVAL;
	int i = 0;
	int written = 0;
	int to_write = 0;
	struct amfs_pattern_info *temp = NULL;
	char *buf = NULL;
	char *temp_db = NULL;
	struct file *fp_org = NULL;
	struct file *fp_tmp = NULL;
	mm_segment_t oldfs;

	if (!spd) {
		pr_err("amfs_update_pattern_db: Invalid amfs_sb_info!\n");
		goto out;
	}

	if (!spd->patt_db_path) {
		pr_err("amfs_update_pattern_db: Invalid pattern db path!\n");
		goto out;
	}

	temp_db = kmalloc(strlen(spd->patt_db_path) + 5,
						__GFP_ZERO|GFP_KERNEL);
	if (!temp_db) {
		pr_err("amfs_update_pattern_db: kmalloc failed for temp_db\n");
		err = -ENOMEM;
		goto out;
	}
	strncpy(temp_db, spd->patt_db_path, strlen(spd->patt_db_path));
	strcat(temp_db, ".tmp");

	fp_org = filp_open(spd->patt_db_path, O_RDONLY, 0);
	if (!fp_org || IS_ERR(fp_org)) {
		pr_err("amfs_update_pattern_db: filp_open err %d\n",
						(int)PTR_ERR(fp_org));
		err = (int) PTR_ERR(fp_org);
		goto out;
	}

	/* Re-set immutable flag for pattern.db file */
	err = amfs_reset_immutable_flag(fp_org);
	if (err)
		goto out;

	fp_tmp = filp_open(temp_db, O_WRONLY|O_CREAT, 0644);
	if (!fp_tmp || IS_ERR(fp_tmp)) {
		pr_err("amfs_update_pattern_db: filp_open err %d\n",
						(int)PTR_ERR(fp_tmp));
		err = (int) PTR_ERR(fp_tmp);
		goto out;
	}

	buf = kmalloc(BUF_LEN_MAX, __GFP_ZERO|GFP_KERNEL);
	if (!buf) {
		pr_err("amfs_update_pattern_db: kmalloc failed for buf!\n");
		err = -ENOMEM;
		goto out;
	}

	fp_tmp->f_pos = 0;
	for (i = 0; i < 96; i++) {
		if (amfs_h_list[i]) {
			temp = amfs_h_list[i];
loop:
			if (temp)
				to_write = strlen(temp->str) + strlen("\n");

			while (temp && ((written + to_write) <= BUF_LEN_MAX)) {
				strcat(buf, temp->str);
				strcat(buf, "\n");
				written += to_write;
				temp = temp->next;
			}
			if ((written + to_write) > BUF_LEN_MAX) {
				oldfs = get_fs();
				set_fs(KERNEL_DS);
				err = vfs_write(fp_tmp, buf, strlen(buf),
								&fp_tmp->f_pos);
				if (err < 0) {
					pr_err("amfs_update_pattern_db: vfs_write failed "
						"for pattern db!\n");
					set_fs(oldfs);
					goto out;
				}
				set_fs(oldfs);
				written = 0;
				memset(buf, 0, BUF_LEN_MAX);
				goto loop;
			}
		}
	}
	if (strlen(buf)) {
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = vfs_write(fp_tmp, buf, strlen(buf), &fp_tmp->f_pos);
		if (err < 0) {
			pr_err("amfs_update_pattern_db: vfs_write failed "
							"for pattern db!\n");
			set_fs(oldfs);
			goto out;
		}
		set_fs(oldfs);
	}

	err = amfs_db_rename(fp_tmp, fp_org);
	if (err) {
		pr_err("amfs_update_pattern_db: amfs_db_rename failed! "
						"err(%d)\n", err);
		goto out;
	}

	/* update remove count of pattern.db */
	if (fp_tmp->f_inode->i_op->setxattr(fp_tmp->f_path.dentry,
						AMFS_REMOVE_COUNT,
						(void *)&(spd->pattern_db_rc),
						sizeof(int), 0)) {
		pr_err("amfs_update_pattern_db: setattr failed for %s "
			"attribute of pattern.db\n", AMFS_REMOVE_COUNT);
	}

	/* set immutable flag of pattern.db */
	err = amfs_set_immutable_flag(fp_tmp);
	if (err)
		goto out;

out:
	if (fp_org && !IS_ERR(fp_org))
		filp_close(fp_org, NULL);
	if (fp_tmp && !IS_ERR(fp_tmp))
		filp_close(fp_tmp, NULL);
	if (spd->patt_db_path)
		kfree(spd->patt_db_path);
	if (temp)
		kfree(temp_db);
	if (buf)
		kfree(buf);
	return err;
}

/**
 * amfs_init_h_list
 * to initialize hashed linked list with malware patterns specified
 * in pattern.db. this is being called during amfs_mount. further
 * modifications related to malware patterns will be done on this
 * list.
 * @spd: amfs superblock info containing path of pattern db
 *
 * input is mandatory
 * returns 0 on success, otherwise negative error value
 */
int amfs_init_h_list(struct amfs_sb_info *spd)
{
	int err = -EINVAL;
	int bytes = 0;
	int i = 0;
	struct file *fp = NULL;
	char *p = NULL;
	char *read_buf = NULL;
	char *read_buf_copy = NULL;
	mm_segment_t oldfs;

	if (!spd || !spd->patt_db_path) {
		pr_err("amfs_init_h_list: Invalid file path!\n");
		goto out;
	}

	read_buf = kmalloc(BUF_LEN_MAX, __GFP_ZERO|GFP_KERNEL);
	if (!read_buf) {
		pr_err("amfs_init_h_list: kmalloc failed for read_buf!\n");
		err = -ENOMEM;
		goto out;
	}

	/* open pattern file */
    fp = filp_open(spd->patt_db_path, O_RDONLY, 0);
    if (!fp || IS_ERR(fp)) {
		pr_err("amfs_init_h_list: filp_open err %d\n",
						(int) PTR_ERR(fp));
		err = (int) PTR_ERR(fp);
		goto out;
    }

	/* Re-set immutable flag for pattern.db file */
	err = amfs_reset_immutable_flag(fp);
	if (err)
		goto out;

	/* Init global values */
	/* inode number of pattern.db file is saved globally */
	/* this is being used to prevent cat operation on pattern.db */
	spd->ino = fp->f_inode->i_ino;

	if (fp->f_inode->i_op->getxattr(fp->f_path.dentry,
					AMFS_REMOVE_COUNT,
					(void *)&(spd->pattern_db_rc),
					sizeof(int)) < 0) {
		/* remove count is not set for pattern.db */
		/* initialize count now */
		spd->pattern_db_rc = AMFS_PATTERN_RC_INIT;
		if (fp->f_inode->i_op->setxattr(fp->f_path.dentry,
						AMFS_REMOVE_COUNT,
						(void *)&(spd->pattern_db_rc),
						sizeof(int), 0)) {
			pr_err("amfs_init_h_list: remove count set failed for "
						"pattern.db\n");
		}
	}
	if (fp->f_inode->i_op->getxattr(fp->f_path.dentry, AMFS_FILE_STATUS,
						(void *)&i, sizeof(int)) < 0) {
		i = AMFS_BAD_VAL;
		/* bad status is not set for pattern.db */
		/* initialize status now */
		if (fp->f_inode->i_op->setxattr(fp->f_path.dentry,
						AMFS_FILE_STATUS,
						(void *)&i,
						sizeof(int), 0)) {
			pr_err("amfs_init_h_list: bad file status set failed "
						"for pattern.db\n");
		}
	}

	/* Initialize hash list with NULL */
	for (i = 0; i < 96; i++)
		amfs_h_list[i] = NULL;

	/* read patterns till BUF_LEN_MAX in one go & add it to the list */
	/* if file size is greater than BUF_LEN_MAX, then it goes in loop */
	fp->f_pos = 0;
	while (fp->f_pos < fp->f_inode->i_size) {
		bytes = ((fp->f_inode->i_size - fp->f_pos) < BUF_LEN_MAX) ?
				(fp->f_inode->i_size - fp->f_pos) : BUF_LEN_MAX;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = vfs_read(fp, read_buf, bytes, &fp->f_pos);
		if (err < 0) {
			pr_err("amfs_init_h_list: vfs_read failed!\n");
			set_fs(oldfs);
			goto out;
		}
		set_fs(oldfs);

		read_buf_copy = read_buf;
		while ((p = strsep(&read_buf_copy, "\n")) != NULL) {
			if (!*p)
				continue;

			if (strlen(p) > AMFSCTL_PATTERN_LEN_MAX) {
				pr_err("amfs_init_h_list: Length too big! "
				"skipping pattern (%s) & adding the rest\n", p);
				continue;
			}

			err = amfs_add_new_pattern(p);
			if (err)
				pr_info("amfs_init_h_list: Failed to add "
						"pattern %s\n", p);
		}
		memset(read_buf, 0, BUF_LEN_MAX);
	}

	/* set immutable flag of pattern.db */
	err = amfs_set_immutable_flag(fp);
	if (err)
		goto out;

out:
	if (fp && !IS_ERR(fp))
		filp_close(fp, NULL);
	if (read_buf)
		kfree(read_buf);
	return err;
}

/**
 * amfs_destroy_h_list
 * to release in-memory list of malware patterns
 *
 * no input is required since list head is global
 */
void amfs_destroy_h_list(void)
{
	int i = 0;
	struct amfs_pattern_info *prev = NULL;
	struct amfs_pattern_info *curr = NULL;

	for (i = 0; i < 96; i++) {
		if (amfs_h_list[i]) {
			prev = amfs_h_list[i];
			curr = amfs_h_list[i];

			while (prev) {
				curr = curr->next;
				kfree(prev->str);
				kfree(prev);
				prev = curr;
			}
			amfs_h_list[i] = NULL;
		}
	}
}
