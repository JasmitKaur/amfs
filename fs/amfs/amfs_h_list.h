/*********************************************************************
 * FILE:	amfs_h_list.h
 * AUTHOR:	jasmit kaur
 * LOGON ID:	110463904
 * DUE DATE:	11/8/2015
 *
 * PURPOSE:	contains type definition for a node of linked list
 *		this is being shared by kernel and user
 *********************************************************************/

#ifndef _AMFS_H_LIST_
#define _AMFS_H_LIST_

/* definition of a node of linked list */
struct amfs_pattern_info {
	char *str;
	struct amfs_pattern_info *next;
};

#endif	/* _AMFS_H_LIST_ */
