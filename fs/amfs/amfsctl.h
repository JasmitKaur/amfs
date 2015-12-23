/*********************************************************************
 * FILE:	amfsctl.h
 * AUTHOR:	jasmit kaur
 * LOGON ID:	110463904
 * DUE DATE:	11/8/2015
 *
 * PURPOSE:	contains ioctl macros to be shared between kernel and
 *		userland
 *********************************************************************/

#ifndef _AMFSCTL_H_
#define _AMFSCTL_H_

#include <linux/ioctl.h>

/* amfsctl argument structure to be passed to ioctl */
struct amfsctl_arg_s {
	int pattern_len;
	char *pattern_str;
};

/* magic number to uniquely identify ioctl */
#define AMFSCTL_MAGIC	'x'

/* customized ioctl commands */
#define AMFSCTL_CNT_PATTERNS	_IOR(AMFSCTL_MAGIC, 0, int *)
#define AMFSCTL_LST_PATTERNS	_IOR(AMFSCTL_MAGIC, 1, struct amfsctl_arg_s*)
#define AMFSCTL_ADD_PATTERNS	_IOW(AMFSCTL_MAGIC, 2, struct amfsctl_arg_s*)
#define AMFSCTL_REM_PATTERNS	_IOW(AMFSCTL_MAGIC, 3, struct amfsctl_arg_s*)

#endif	/*_AMFSCTL_H_ */
