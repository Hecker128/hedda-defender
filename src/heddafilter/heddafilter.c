#include <stdint.h>
#include <fltkernel.h>

static PFLT_FILTER filter;
static PFLT_PORT client_port = NULL;

// TODO: Idk what to call this function yet. Rename it sometime.
void try_send_msg(void *buf, uint32_t len) {
	if (client_port == NULL) return;
	FltSendMessage(filter, client_port, buf, len, NULL, NULL, NULL);
}

FLT_PREOP_CALLBACK_STATUS heddafilter_create_preoperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
) {
	if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->Iopb->OperationFlags & SL_OPEN_TARGET_DIRECTORY) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (!Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_EXECUTE) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//Data->Iopb->OperationFlags & SL_CASE_SENSITIVE;

	PFLT_FILE_NAME_INFORMATION name_info;
	if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &name_info))) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	try_send_msg(name_info->Name.Buffer, name_info->Name.Length);

	FltReleaseFileNameInformation(name_info);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS heddafilter_unload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	 FltUnregisterFilter(filter);
	 return STATUS_SUCCESS;
}

NTSTATUS heddafilter_connect(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID *ConnectionCookie
) {
	client_port = ClientPort;
	return STATUS_SUCCESS;
}

NTSTATUS heddafilter_message(
	PVOID ConnectionCookie,
	PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	return STATUS_SUCCESS;
}

NTSTATUS heddafilter_disconnect(PVOID ConnectionCookie) {
	FltCloseClientPort(filter, &client_port);
	return STATUS_SUCCESS;
}

__declspec(code_seg("INIT"))
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	static const FLT_CONTEXT_REGISTRATION contexts[] = {
		{ FLT_CONTEXT_END }
	};
	static const FLT_OPERATION_REGISTRATION operations[] = {
		{
			.MajorFunction = IRP_MJ_CREATE,
			.Flags = 0,
			.PreOperation = heddafilter_create_preoperation,
		},
		{ IRP_MJ_OPERATION_END }
	};
	static const FLT_REGISTRATION registration = {
		.Size = sizeof(registration),
		.Version = FLT_REGISTRATION_VERSION,
		.Flags = 0,
		.ContextRegistration = contexts,
		.OperationRegistration = operations,
		.FilterUnloadCallback = heddafilter_unload,
	};

	NTSTATUS status = FltRegisterFilter(DriverObject, &registration, &filter);
	if (!NT_SUCCESS(status)) return status;

	UNICODE_STRING port_name;
	RtlInitUnicodeString(&port_name, L"HeddafilterPort");

	SECURITY_DESCRIPTOR sec_desc;
	status = FltBuildDefaultSecurityDescriptor(&sec_desc, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status)) goto fail_unregister;

	OBJECT_ATTRIBUTES attrs;
	InitializeObjectAttributes(
		&attrs,
		&port_name,
		OBJ_KERNEL_HANDLE,
		NULL,
		&sec_desc
	);
	if (!NT_SUCCESS(status)) goto fail_unregister;

	PFLT_PORT port;
	status = FltCreateCommunicationPort(
		filter,
		&port,
		&attrs,
		NULL,
		heddafilter_connect,
		heddafilter_disconnect,
		heddafilter_message,
		1
	);
	if (!NT_SUCCESS(status)) goto fail_unregister;

	status = FltStartFiltering(filter);
	if (!NT_SUCCESS(status)) goto fail_unregister;

	return status;

	fail_unregister:
	FltUnregisterFilter(filter);
	return status;
}
