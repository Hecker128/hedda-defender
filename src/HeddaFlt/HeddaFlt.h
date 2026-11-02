#pragma once

#define HEDDAFLT_MSG_ERROR 0
#define HEDDAFLT_MSG_PRE_CREATE 1
#define HEDDAFLT_MSG_PLEASE_DONT_GHOST_ME 2

#define HEDDAFLT_EC_FLT_SEND_MESSAGE_FAILED 0

typedef struct {
	ULONG kind; // HEDDAFLT_MSG_ERROR, etc.
	union {
		struct {
			NTSTATUS status;
			ULONG context; // HEDDAFLT_EC_FLT_SEND_MESSAGE_FAILED, etc.
		} error;
		struct {
			USHORT path_sz;
			USHORT _reserved;
			ACCESS_MASK desired_access;
		} pre_create;
	} kind_union;
	ULONG _reserved;
	WCHAR body[256];
} HeddaFltMsg;

typedef struct {
	BOOLEAN operation_allowed;
} HeddaFltReply;