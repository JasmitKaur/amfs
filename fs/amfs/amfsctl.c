/*********************************************************************
 * FILE:	amfsctl.c
 * AUTHOR:	jasmit kaur
 * LOGON ID:	110463904
 * DUE DATE:	11/8/2015
 *
 * PURPOSE:	provides user interaction to list, add or remove
 *		malware patterns to/from pattern.db
 *********************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include "amfsctl.h"

/* restricting max len of a malware pattern */
#define AMFSCTL_PATTERN_LEN_MAX	256

/**
 * main - entry of program
 * @argc: count of total arguments
 * @argv: array of argument values
 *
 * ref : provided inline alongwith APIs
 */
int main(int argc, char *argv[])
{
	char *pattern_db = "/mnt/amfs";
	int fd;
	int ret = -1;
	int c;
	extern char *optarg;
	extern int optind, optopt;
	enum {
		e_list,
		e_add,
		e_rem
	} opt;
	struct amfsctl_arg_s *p_amfsctl_arg = NULL;

	p_amfsctl_arg = malloc(sizeof(struct amfsctl_arg_s));
	if (!p_amfsctl_arg) {
		perror("amfs: malloc failed for p_amfsctl_arg\n");
		goto exit;
	}

	opt = -1;
	while ((c = getopt(argc, argv, "la:r:")) != -1) {
		switch (c) {
		case 'l':
			opt = e_list;
			break;
		case 'a':
			if (strlen(optarg) > AMFSCTL_PATTERN_LEN_MAX) {
				fprintf(stderr, "amfs: Max length allowed for a "
					"malware pattern is %d\n",
					AMFSCTL_PATTERN_LEN_MAX);
				goto clean_exit;
			}
			opt = e_add;
			p_amfsctl_arg->pattern_str =
					malloc(strlen(optarg) * sizeof(char));
			if (!p_amfsctl_arg->pattern_str) {
				perror("amfs: malloc failed for pattern_str\n");
				goto clean_exit;
			}
			strncpy(p_amfsctl_arg->pattern_str, optarg,
								strlen(optarg));
			p_amfsctl_arg->pattern_len =
					strlen(p_amfsctl_arg->pattern_str);
			break;
		case 'r':
			if (strlen(optarg) > AMFSCTL_PATTERN_LEN_MAX) {
				fprintf(stderr, "amfs: Max length allowed for a "
						"malware pattern is %d\n",
						AMFSCTL_PATTERN_LEN_MAX);
				goto clean_exit;
			}
			opt = e_rem;
			p_amfsctl_arg->pattern_str =
					malloc(strlen(optarg) * sizeof(char));
			if (!p_amfsctl_arg->pattern_str) {
				perror("amfs: malloc failed for pattern_str\n");
				goto clean_exit;
			}
			strncpy(p_amfsctl_arg->pattern_str, optarg,
								strlen(optarg));
			p_amfsctl_arg->pattern_len =
					strlen(p_amfsctl_arg->pattern_str);
			break;
		case '?':
			printf("Invalid parameters! Try again!\n");
			printf("List patterns: ./amfsctl -l /mnt/amfs\n");
			printf("Add pattern: ./amfsctl -a \"new pattern\" "
							"/mnt/amfs\n");
			printf("Remove pattern: ./amfsctl -r \"existing "
					"pattern\" /mnt/amfs\n");
			goto clean_exit;
		}
	}

	if (((argc - optind) != 1) || (opt == -1)) {
		/* number or args are more than required */
		printf("amfs: Invalid command! Try again!\n");
		goto clean_exit;
	}
	if (strncmp(argv[optind], "/mnt/amfs", strlen("/mnt/amfs"))) {
		printf("amfs: Mount points are different! \n");
		goto clean_exit;
	}

	fd = open(pattern_db, O_RDONLY);
	if (fd == -1) {
		perror("amfs: Unable to open pattern.db! \n");
		goto clean_exit;
	}

	switch (opt) {
	case e_list:
	{
		int len = 0;
		if (ioctl(fd, AMFSCTL_CNT_PATTERNS, &len)) {
			perror("amfs: ioctl failed for count! "
				"Check dmesg for more information!\n");
			goto fd_exit;
		}
			if (len) {
			p_amfsctl_arg->pattern_len = len;

			p_amfsctl_arg->pattern_str = malloc(
			(p_amfsctl_arg->pattern_len + 1) * sizeof(char));
			if (!p_amfsctl_arg->pattern_str) {
				perror("amfs: malloc failed for "
						"pattern_str\n");
				goto fd_exit;
			}
			if (ioctl(fd, AMFSCTL_LST_PATTERNS, p_amfsctl_arg)) {
				perror("amfs: ioctl failed while listing patterns!"
					"Check dmesg for more information!\n");
				goto fd_exit;
			}
			printf("%s", p_amfsctl_arg->pattern_str);
		} else {
			printf("amfs: No patterns found! pattern.db is empty!\n"
					"Add pattern using following command: "
					"./amfsctl -a \"new pattern\" /mnt/amfs\n");
		}
	}
	break;
	case e_add:
	{
		if (ioctl(fd, AMFSCTL_ADD_PATTERNS, p_amfsctl_arg)) {
			perror("amfs: ioctl failed while adding patterns!"
					"Check dmesg for more information!\n");
			goto fd_exit;
		}
		printf("pattern added successfully\n");
	}
	break;
	case e_rem:
	{
		if (ioctl(fd, AMFSCTL_REM_PATTERNS, p_amfsctl_arg)) {
			perror("amfs: ioctl failed while removing patterns!"
					"Check dmesg for more information!\n");
			goto fd_exit;
		}
		printf("pattern removed successfully\n");
	}
	break;
	default:
	break;
    }
fd_exit:
	if (fd)
		close(fd);
clean_exit:
	if (p_amfsctl_arg->pattern_str)
		free(p_amfsctl_arg->pattern_str);
	if (p_amfsctl_arg)
		free(p_amfsctl_arg);
exit:
	return ret;
}
