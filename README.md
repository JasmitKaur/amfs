# Anti-malware Stackable File System (AMFS)

INTRODUCTION:
	A stackable file system is stand alone file system, inserted
	right between VFS and lower layer native file systems in kernel.
	Anti-malware file system (amfs) is a stackable file system,
	stacks on top of native file system (ext3, in this case), to
	detect and prevent attempts to read/write 'bad' files.

HOW DOES IT WORK?
	A file is 'bad' if it contains atleast one malware pattern. AMFS
	takes pattern database file while mounting, initializes in-
	memory data structure for pattern.db, scans file for malware
	patterns during read / write operations and sets file attribute
	as bad (quarantine the file) if at least one malware pattern is
	is found in file. Also, it prevents the listing of such files
	which are marked as bad.

CODING APPROACH
	AMFS is written by copying basic functions/symbols from wrapfs.
	Anti-malware functionalities and support for pattern database
	management is added on top of renamed wrapfs source code.

PROJECT FILES
	From wrapfs:
	- main.c:	to define file system type, to initialize and
			register amfs
	- super.c:	to release allocated instances of amfs and
			unmounting amfs
	- file.c:	to define file operations such as read, write,
			open, close etc
	- inode.c:	to define inode operations such as create, link
			unlink, lookup, getattr, setattr etc
	- dentry.c:	to define dentry operations such as release,
			revalidate etc
	- lookup.c:	to define lookup and supporting methods such as
			establishing link between amfs and lower fs
			objects
	- mmap.c:	to define address space, memory management
			operations
	- amfs.h:	includes definition of macros and methods being
			used in amfs
	- Makefile:	build instructions
	- Kconfig:	to include amfs as miscellaneous/experimental
			file system in menuconfig

	Additional files:
	- amfsctl.c:	to provide user interation/support for pattern
			db management, such as list, add or remove
			patterns to/from pattern.db
	- amfsctl.h:	to include ioctl macros to be shared between
			kernel and userland
	- amfs_h_list.c:	to define methods for linked list
				modification, as hashed linked list is
				being used for in-memory representation
				of  pattern.db
	- amfs_h_list.h:	to include definition for a node of
				linked list
	- amfs_utility.c:	to define utility methods such as, set/
				reset immutable flags, check validity
				of mount options etc

	Modified files
	- include/uapi/linux/magic.h: Added magic number for amfs
				AMFS_SUPER_MAGIC (0x231F)
	- fs/Kconfig:	to include source "fs/amfs/Kconfig"
	- fs/Makefile:	to add amfs file system

HOW TO BUILD?
	- # cd hw2-jsaluja/fs/amfs
	- hw2-jsaluja/fs/amfs# make
	- hw2-jsaluja/fs/amfs# cd ../../
	- hw2-jsaluja# make
	- hw2-jsaluja# make modules
	- hw2-jsaluja# make modules_install install
	- hw2-jsaluja# reboot

HOW TO EXECUTE?
	- hw2-jsaluja# mkdir /mnt/hw2
	- hw2-jsaluja# mount /dev/sda1 /mnt/hw2
	- hw2-jsaluja# mkdir /mnt/amfs
	- hw2-jsaluja# rmmod fs/amfs/amfs.ko
	- hw2-jsaluja# insmod fs/amfs/amfs.ko
	- hw2-jsaluja# mount -t amfs -o pattdb=/pattern.db /mnt/hw2 /mnt/amfs

MOUNT OPTIONS
	-o pattdb=/pattern.db
	This is the mount option to be provided while mounting amfs. It
	should follow below mentioned specifications:
	- Should not be comma separated, i.e. multiple options are not
		supported in amfs
	- Should start with 'pattdb='
	- File path can be relative to /mnt/hw2, eg: if pattern.db is in
		/mn/hw2/test/pattern.db then mount option should be
		-o pattdb=/test/pattern.db OR
		-o pattdb=test/pattern.db

PATTERN DATABASE
	A simple file containing plain text, one per line, delimited by
	'\n'. We call it a malware pattern.
	- Specifications:
		- file should reside in lower fs which is being used
			for mount (/mnt/hw2 in this case)
		- file should have read / write permissions
		- file name should NOT contain ',' (comma character)
		- length of pattern is restricted to max 256 characters

	- In-memory data structure
		For efficiency, the content of pattern.db is stored in
		hashed linked lists. An array of size 96 is being used
		to store the heads of linked lists.

		- Why 96?
			ASCII values of a char goes from 0 to 127, of
			which first 32 (i.e. 0 to 31) can not be a first
			char of our pattern. Hence 128 - 32 = 96

		- Hash function?
			h(pattern_x) = ASCII value of first char of
					pattern_x - 32

		- How is this efficient?
			This data structure is quite efficient while
			searching if pattern exists in db. For eg:
			while adding a pattern, we need to make sure
			that given pattern does not exists in db. For
			this, all  it has to do is generate a hash from
			first char of a pattern and check ONLY in the
			corresponding linked list.

		- Support for data structure management
			Support for addition of new pattern (node) in
			linked list, deletion of existing node, and
			traversal of complete db is provided in file
			amfs_h_list.c

	- User level support of pattern management:
		User can list, add or remove malware patterns using
		amfsctl commands. amfsctl is executable file generated
		by gcc command. This program calls amfs_unlocked_ioctl
		with specific ioctl cmd defined for list, add and remove

		- list:
			./amfsctl -l /mnt/amfs
			- calls an ioctl to get size of pattern.db
			- malloc for length returned from prev ioctl
			- calls ioctl to get a list of patterns in in-
				memory data structure
			- prints the resturned list
		- add
			./amfsctl -a "newpattern" /mnt/amfs
			- calls an ioctl to add new pattern to in-memory
				data structure
			- prints success/failure message
		- remove
			./amfsctl -r "oldpattern" /mnt/amfs
			- calls an ioctl to remove existing pattern from
				 in-memory data structure
			- prints success/failure message

	- Update policy:
		database file is being accessed only twice, i.e.
		- on mount
			hashed linked list will be initialize after
			reading the content of db file
		- on umount
			the content of hashed linked list will be
			written back to db file
			(For this step, amfs is writing the data in .tmp
			file and renaming it to be the original db file)
		in-between mount and umount, all the modifications are
		being done on hashed linked list.

	- Immutable policy
		Setting immutable flag of a file prevents it from being
		modified, renamed, delete, copy, read or write.
		- once hashed linked list is initialized, amfs will set
			immutable flag of pattern.db, so that no-one can
			modify or delete the file.
		- before unmounting amfs, it will set immutable flag of
			db file, so that it can not be modified manually
		- amfs will reset immutable flag whenever it needs to
			access the file and set it back once done.

	- Versioning
		amfs maintains the remove count of patterns from db.
		this remove count is being used as version of pattern.db
		and is used to decide whether re-scanning of bad file is
		required or not.

'QUARANTINE' POLICY
	The process of setting 'bad' attribute of file, if it contains
	atleast one malware pattern, is called quarantine.
	In amfs, this is being done only in amfs_read / amfs_write,
	considering the intension behind opening a file would be either
	read or write operation.

	- amfs_read
		If vfs_read is performed successfully, the __user buf
		will have valid data. If so then,
		check if 'bad' and 'rc' attributes of file being read
		are set
		- If yes then this was a 'bad' file,
			- check if 'rc' attribute of file matches
	                        with remove count(version) of pattern.db
			- If so, then this is still a bad file,
				return -EPERM
			- Else if version does not matches, i.e. some
				patterns have been removed from pattern
				db, i.e. need to scan bad file again
				- If found bad, then set 'bad' and 'rc'
					attributes and return -EPERM
				- Else file is good now, both attributes
					has to be removed

		- else either good file or a new file, need to scan in
			both the cases
			- If found bad, then set 'bad' and 'rc'
				attributes and return -EPERM

	- amfs_write
		If vfs_read is successful then, the __user buf will have
		valid data to be scanned. If so then,
		check if 'bad' and 'rc' attributes of file being written
                are set
		- If yes, then this is a bad file.
			i.e. this can not be a new file, as amfs sets 'bad'
			attributes only in read / write.
			i.e. the execution will go to amfs_read, before
			coming to amfs_write.
			i.e. the operation would have blocked in read
			itself. Hence this case has not been handled in
			amfs_write.
		- If no, then this is either new or a good file.
			- scan to check if it contains malware patterns
			- If yes, then add 'bad' and 'rc' attributes
			and allow write.

LIMITATIONS
	- Patterns that cross user buffers (of size 4096) is not being
		handled. As per current implementation, amfs will split
		that pattern into two halves and save as 2 different
		patterns in memory (linked list).
	- For simplicity, length of a pattern is restricted to max 256
		characters.
	- Only 'bad' state of file is being maintained.
		If file was scanned before and found good, even then
		it needs to be scanned in next read/write, as no
		attribute is being set for good file.
	- Immutable flag can be reset manually using chattr command.
		after which pattern.db file can be accessed / modified.
	- 'bad' or 'rc' attributes of file being read / write can be
		modified manually using 'setfattr' command.
	- In between mount and umnount, all the modifications related
		to malware patters are being done on hashed linked list.
		Hence if system crashes in-between, then new pattern list
		will be lost.

KNOWN BUGS
	- To perform atomic write of pattern.db file, the list of
		patterns are being written to .tmp file and then is
		being renamed to original. But file permissions of new
		file (.tmp file) is set to be default and not the same
		as original pattern.db file.
	- 'ls' operation lists all good or bad files for the first time
		after mount. From 2nd time onwards, it is working
		properly ( i.e. hiding all the bad files from listing).

REFERENCES:
1. Lxr for understanding of existing APIs and structures
	http://lxr.fsl.cs.sunysb.edu/linux/source/
2. ecryptfs
	for readdir and filldir
3. Class notes provided by Prof. Erez Zadok


PS: Please send me an email at jasmit.saluja@stonybrook.edu for code.