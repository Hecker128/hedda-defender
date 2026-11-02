#pragma warning(disable: 4100 4702)

#include <fltKernel.h>
#include "HeddaFlt.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS unload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS query_teardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
NTSTATUS connect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionCookie);
NTSTATUS disconnect(PVOID ConnectionCookie);
NTSTATUS message(PVOID ConnectionCookie, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);

#ifdef ALLOC_PRAGMA
# pragma alloc_text(INIT, DriverEntry)
# pragma alloc_text(PAGE, unload)
# pragma alloc_text(PAGE, query_teardown)
# pragma alloc_text(PAGE, connect)
# pragma alloc_text(PAGE, disconnect)
# pragma alloc_text(PAGE, message)
#endif

PFLT_FILTER filter;
PFLT_PORT client_port = NULL;
PFLT_PORT server_port;

/// Helper for `send_error_message` and `send_pre_create_message`.
/// Like the `ReplyBuffer` argument to `FltSendMessage`, `reply` is optional
/// and can be `NULL`.
NTSTATUS send_message_with_timeout(HeddaFltMsg *msg, HeddaFltReply *reply, ULONG timeout_millis) {
	LARGE_INTEGER timeout = { .QuadPart = -10 * 1000 * timeout_millis };
	ULONG reply_sz = sizeof(HeddaFltReply);
	return FltSendMessage(filter, &client_port, msg, sizeof(*msg), reply, (reply == NULL) ? NULL : &reply_sz, &timeout);
}

void send_error_message(NTSTATUS status, ULONG context) {
	if (client_port == NULL) return;

	static HeddaFltMsg msg;
	msg = (HeddaFltMsg){
		.kind = HEDDAFLT_MSG_ERROR,
		.kind_union.error.status = status,
		.kind_union.error.context = context,
	};
	send_message_with_timeout(&msg, NULL, 1000);
}

BOOLEAN send_pre_create_message(PFLT_CALLBACK_DATA data) {
	if (client_port == NULL) return TRUE;

	USHORT path_sz = data->Iopb->TargetFileObject->FileName.Length;

	static HeddaFltMsg msg;
	msg = (HeddaFltMsg){
		.kind = HEDDAFLT_MSG_PRE_CREATE,
		.kind_union.pre_create.path_sz = path_sz,
		.kind_union.pre_create.desired_access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
	};
	for (USHORT i = 0; i < path_sz; i += sizeof(msg.body)) {
		RtlCopyMemory(
			msg.body,
			(UCHAR *)data->Iopb->TargetFileObject->FileName.Buffer + i,
			(path_sz - i < sizeof(msg.body)) ? path_sz - i : sizeof(msg.body)
		);
		NTSTATUS status = send_message_with_timeout(&msg, NULL, 1000);
		if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT) {
			send_error_message(status, HEDDAFLT_EC_FLT_SEND_MESSAGE_FAILED);
			return TRUE;
		}
	}

	msg.kind = HEDDAFLT_MSG_PLEASE_DONT_GHOST_ME;
	HeddaFltReply reply;
	NTSTATUS status = send_message_with_timeout(&msg, &reply, 1000);
	if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT) {
		send_error_message(status, HEDDAFLT_EC_FLT_SEND_MESSAGE_FAILED);
		return TRUE;
	}
	return reply.operation_allowed;
}

/// `PreOperation` callback for `IRP_MJ_CREATE`.
/// Messages the usermode part of Hedda Defender when a create operation happens
/// that should be investigated (e.g. if a possibly malicious file is opened for
/// execution).
FLT_PREOP_CALLBACK_STATUS create_preop(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (!(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & STANDARD_RIGHTS_EXECUTE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->Iopb->OperationFlags & SL_OPEN_TARGET_DIRECTORY) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	// FIXME: There are more things worth checking before scanning I think.

	if (send_pre_create_message(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
	// Operation disallowed
	Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	Data->IoStatus.Information = 0;
	return FLT_PREOP_COMPLETE;
}

/// Helper for `DriverEntry`.
/// Creates a communication server port, initializing `server_port`.
NTSTATUS create_comm_port() {
	UNICODE_STRING port_name;
	RtlInitUnicodeString(&port_name, L"\\HeddaFltPort");

	PSECURITY_DESCRIPTOR security;
	NTSTATUS status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status)) return status;

	OBJECT_ATTRIBUTES attrs;
	InitializeObjectAttributes(&attrs, &port_name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, security);

	return FltCreateCommunicationPort(filter, &server_port, &attrs, NULL, connect, disconnect, message, 1);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = FltRegisterFilter(
		DriverObject,
		&(FLT_REGISTRATION){
			.Size = sizeof(FLT_REGISTRATION),
			.Version = FLT_REGISTRATION_VERSION,
			.OperationRegistration = (FLT_OPERATION_REGISTRATION[]){
				{
					.MajorFunction = IRP_MJ_CREATE,
					.PreOperation = create_preop,
				},
				{ IRP_MJ_OPERATION_END }
			},
			.FilterUnloadCallback = unload,
			.InstanceQueryTeardownCallback = query_teardown,
		},
		& filter
	);
	if (!NT_SUCCESS(status)) return status;

	status = create_comm_port();
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(filter);
		return status;
	}

	status = FltStartFiltering(filter);
	if (!NT_SUCCESS(status)) {
		FltCloseCommunicationPort(server_port);
		FltUnregisterFilter(filter);
	}
	return status;
}

NTSTATUS unload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	PAGED_CODE();

	FltCloseCommunicationPort(server_port);
	FltUnregisterFilter(filter);
	return STATUS_SUCCESS;
}

NTSTATUS query_teardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
	PAGED_CODE();

	return STATUS_SUCCESS;
}

NTSTATUS connect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionCookie) {
	PAGED_CODE();

	client_port = ClientPort;
	return STATUS_SUCCESS;
}

NTSTATUS disconnect(PVOID ConnectionCookie) {
	PAGED_CODE();

	FltCloseClientPort(filter, &client_port);
	return STATUS_SUCCESS;
}

NTSTATUS message(PVOID ConnectionCookie, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	PAGED_CODE();

	return STATUS_SUCCESS;
}
