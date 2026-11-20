/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_FILE_H
#define _UAPI_PKM_FILE_H

#include <linux/types.h>

/*
 * KACS file ABI — kacs_open (SYS_KACS_OPEN) and the mount-policy syscalls
 * (SYS_KACS_GET_MOUNT_POLICY / SYS_KACS_SET_MOUNT_POLICY).
 *
 * kacs_open is the native, NtCreateFile-shaped open: kacs_open_how
 * describes the desired access, create disposition, create options, and an
 * optional security descriptor applied to a newly-created file.
 *
 * The file-specific right bits below occupy the low 16 bits of an access
 * mask; the standard and generic bits are in <pkm/sd.h>. libp builds the
 * file struct kacs_generic_mapping (see <pkm/sd.h>) from these bits.
 */

/*
 * kacs_open "how" descriptor. The structure is size-versioned: a caller
 * passes the size it was built with, and fields beyond that size read as
 * zero. share_access is read only with KACS_OPEN_SHARE_ACCESS and must
 * otherwise be zero; lease_key and lease_fd are read only with
 * KACS_OPEN_LEASE_KEY. __pad2 must be zero.
 */
struct kacs_open_how {
	__u32 desired_access;
	__u32 create_disposition;
	__u32 create_options;
	__u32 flags;
	__u64 sd_ptr;
	__u32 sd_len;
	__u32 share_access;
	__u8 lease_key[16];
	__s32 lease_fd;
	__u32 __pad2;
};

/*
 * kacs_query_open result. The structure is size-versioned: the kernel
 * writes at most the size the caller passes.
 */
struct kacs_open_info {
	__u32 granted_access;
	__u32 share_access;
	__u32 flags;
	__u32 __pad;
};

/*
 * kacs_lock arguments. A lock covers length bytes from offset; a zero
 * length is a point. cookie names a waiting request for KACS_LOCK_CANCEL.
 */
struct kacs_lock_args {
	__u64 offset;
	__u64 length;
	__u32 op;
	__u32 flags;
	__u64 cookie;
};

/* kacs_lease arguments. __pad must be zero. */
struct kacs_lease_args {
	__u8 lease_key[16];
	__u32 state;
	__u32 flags;
	__u64 __pad;
};

/*
 * A break notice, read from a lease-manager descriptor. epoch counts the
 * breaks of this lease, so a stale acknowledgement can be told apart.
 */
struct kacs_lease_break {
	__u8 lease_key[16];
	__u64 dev;
	__u64 ino;
	__u32 current_state;
	__u32 new_state;
	__u32 reason;
	__u32 epoch;
};

/* Argument block for the mount-policy syscalls. __pad fields must be zero. */
struct kacs_mount_policy_args {
	__u32 policy;
	__u32 flags;
	__u32 generation;
	__u32 __pad0;
	__u64 template_sd_ptr;
	__u32 template_sd_len;
	__u32 __pad1;
};

/*
 * The value of the special-attributes extended attribute, as read and as
 * written. valid names the fields a write changes; a read sets every bit.
 * Other fields a write does not name are ignored, and __pad must be zero.
 */
#define KACS_SATTR_XATTR_NAME "security.peios.sattr"

struct kacs_sattr {
	__u32 version;
	__u32 valid;
	__u32 attributes;
	__u32 flags;
	__s64 created_at_sec;
	__u32 created_at_nsec;
	__u32 __pad;
};

/* Minimum caller-supplied size accepted for each argument block. */
#define KACS_OPEN_HOW_MIN_SIZE 16U
#define KACS_MOUNT_POLICY_ARGS_MIN_SIZE 16U
#define KACS_OPEN_INFO_MIN_SIZE 4U
#define KACS_LOCK_ARGS_MIN_SIZE 24U
#define KACS_LEASE_ARGS_MIN_SIZE 24U

/* Sizes of each published version of kacs_open_how. */
#define KACS_OPEN_HOW_SIZE_VER0 32U
#define KACS_OPEN_HOW_SIZE_VER1 56U

/* Create dispositions (kacs_open_how.create_disposition). */
#define KACS_DISPOSITION_SUPERSEDE 0U
#define KACS_DISPOSITION_OPEN 1U
#define KACS_DISPOSITION_CREATE 2U
#define KACS_DISPOSITION_OPEN_IF 3U
#define KACS_DISPOSITION_OVERWRITE 4U
#define KACS_DISPOSITION_OVERWRITE_IF 5U

/* Create options (kacs_open_how.create_options). */
#define KACS_CREATE_OPT_DIRECTORY 0x0001U
#define KACS_CREATE_OPT_DELETE_ON_CLOSE 0x0002U

/* kacs_open_how.flags bits. */
#define KACS_BACKUP_INTENT 0x00000001U
#define KACS_RESTORE_INTENT 0x00000002U
#define KACS_OPEN_SHARE_ACCESS 0x00000004U
#define KACS_OPEN_LEASE_KEY 0x00000008U
#define KACS_OPEN_PIN_ANCESTORS 0x00000010U

/* Share access (kacs_open_how.share_access, kacs_open_info.share_access). */
#define KACS_FILE_SHARE_READ 0x00000001U
#define KACS_FILE_SHARE_WRITE 0x00000002U
#define KACS_FILE_SHARE_DELETE 0x00000004U

/* kacs_open_info.flags bits. */
#define KACS_OPEN_INFO_MANAGED 0x00000001U
#define KACS_OPEN_INFO_DELETE_PENDING 0x00000002U
#define KACS_OPEN_INFO_DELETE_ON_CLOSE 0x00000004U
#define KACS_OPEN_INFO_ANCESTORS_PINNED 0x00000008U

/* kacs_set_disposition flags, as FILE_DISPOSITION_INFORMATION_EX. */
#define KACS_DISPOSITION_DELETE 0x00000001U
#define KACS_DISPOSITION_POSIX_SEMANTICS 0x00000002U
#define KACS_DISPOSITION_ON_CLOSE 0x00000008U
#define KACS_DISPOSITION_IGNORE_READONLY 0x00000010U

/* kacs_rename flags, as FILE_RENAME_INFORMATION_EX. */
#define KACS_RENAME_REPLACE_IF_EXISTS 0x00000001U
#define KACS_RENAME_POSIX_SEMANTICS 0x00000002U
#define KACS_RENAME_IGNORE_READONLY 0x00000040U

/* kacs_lock_args.op values. */
#define KACS_LOCK_SHARED 1U
#define KACS_LOCK_EXCLUSIVE 2U
#define KACS_LOCK_UNLOCK 3U
#define KACS_LOCK_CANCEL 4U

/* kacs_lock_args.flags bits. */
#define KACS_LOCK_FAIL_IMMEDIATELY 0x00000001U

/* Lease states: the NT caching bits. */
#define KACS_LEASE_READ 0x00000001U
#define KACS_LEASE_HANDLE 0x00000002U
#define KACS_LEASE_WRITE 0x00000004U

/* kacs_lease_args.flags bits. */
#define KACS_LEASE_ACKNOWLEDGE 0x00000001U

/* kacs_lease_break.reason values: the operation that broke the lease. */
#define KACS_LEASE_BREAK_OPEN 1U
#define KACS_LEASE_BREAK_SHARING 2U
#define KACS_LEASE_BREAK_WRITE 3U
#define KACS_LEASE_BREAK_SIZE 4U
#define KACS_LEASE_BREAK_LOCK 5U
#define KACS_LEASE_BREAK_NAMESPACE 6U
#define KACS_LEASE_BREAK_DELETE 7U
#define KACS_LEASE_BREAK_SECURITY 8U
#define KACS_LEASE_BREAK_ATTRIBUTES 9U
#define KACS_LEASE_BREAK_CHILD 10U
#define KACS_LEASE_BREAK_TIMEOUT 11U

/* kacs_create_lease_manager flags. */
#define KACS_LEASE_MANAGER_CLOEXEC 0x00000001U
#define KACS_LEASE_MANAGER_NONBLOCK 0x00000002U

/* Break timeout applied when kacs_create_lease_manager is given zero. */
#define KACS_LEASE_DEFAULT_BREAK_TIMEOUT_MS 35000U

/* kacs_sattr.version. */
#define KACS_SATTR_VERSION 1U

/* kacs_sattr.valid bits. */
#define KACS_SATTR_VALID_ATTRIBUTES 0x00000001U
#define KACS_SATTR_VALID_CREATED_AT 0x00000002U

/* kacs_sattr.attributes bits. */
#define KACS_SATTR_READONLY 0x00000001U

/*
 * kacs_sattr.flags bits. On a read, CREATED_AT_SET says Created At was set
 * explicitly rather than taken from the birth time. On a write naming
 * KACS_SATTR_VALID_CREATED_AT, CREATED_AT_CLEAR unsets it.
 */
#define KACS_SATTR_CREATED_AT_SET 0x00000001U
#define KACS_SATTR_CREATED_AT_CLEAR 0x00000002U

/*
 * File and directory object-specific access rights (the low 16 bits of a
 * file access mask). The directory aliases name the same bit as the file
 * right it acts as for a directory object.
 */
#define KACS_FILE_READ_DATA 0x00000001U
#define KACS_FILE_WRITE_DATA 0x00000002U
#define KACS_FILE_APPEND_DATA 0x00000004U
#define KACS_FILE_READ_EA 0x00000008U
#define KACS_FILE_WRITE_EA 0x00000010U
#define KACS_FILE_EXECUTE 0x00000020U
#define KACS_FILE_DELETE_CHILD 0x00000040U
#define KACS_FILE_READ_ATTRIBUTES 0x00000080U
#define KACS_FILE_WRITE_ATTRIBUTES 0x00000100U

#define KACS_FILE_LIST_DIRECTORY KACS_FILE_READ_DATA
#define KACS_FILE_TRAVERSE KACS_FILE_EXECUTE
#define KACS_FILE_ADD_FILE KACS_FILE_WRITE_DATA
#define KACS_FILE_ADD_SUBDIRECTORY KACS_FILE_APPEND_DATA

/* Mount-policy values (kacs_mount_policy_args.policy). */
#define KACS_MOUNT_POLICY_UNMANAGED 1U
#define KACS_MOUNT_POLICY_DENY_MISSING 2U
#define KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3U
#define KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT 4U

/* Status word kacs_open writes back, describing what happened to the file. */
#define KACS_STATUS_OPENED 1U
#define KACS_STATUS_CREATED 2U
#define KACS_STATUS_OVERWRITTEN 3U
#define KACS_STATUS_SUPERSEDED 4U

/*
 * Status word kacs_open writes back when it fails, naming the NT condition
 * behind the errno where one errno covers several.
 */
#define KACS_STATUS_SHARING_VIOLATION 0x10U
#define KACS_STATUS_DELETE_PENDING 0x11U
#define KACS_STATUS_CANNOT_DELETE 0x12U

#endif /* _UAPI_PKM_FILE_H */
