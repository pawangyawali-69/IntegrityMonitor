#include <ntddk.h>
#include <ntstrsafe.h>
#include "IntegrityMonitor.h"

#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)

#define POOL_TAG 'tIOM'
#define MAX_EVENTS 4096
#define MAX_PROCESS_NAME_COPY 252
#define MAX_IMAGE_PATH_COPY 256

typedef struct _INTEGRITY_EVENT_ENTRY {
    LIST_ENTRY ListEntry;
    INTEGRITY_EVENT Event;
} INTEGRITY_EVENT_ENTRY;

static LIST_ENTRY g_EventListHead;
static KSPIN_LOCK g_EventListLock;
static ULONG g_EventCount = 0;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static PVOID g_ObCallbackRegistration = NULL;
static UNICODE_STRING g_DevName;
static UNICODE_STRING g_SymLink;

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverCreateClose;
DRIVER_DISPATCH DriverDeviceControl;

NTSTATUS AddEventToList(ULONG eventType, ULONG pid, const wchar_t* processName,
    const wchar_t* imagePath, ULONG targetPid, ULONG handleId, BOOLEAN isSuspicious);
VOID ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
VOID ImageLoadNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
OB_PREOP_CALLBACK_STATUS HandlePreOperationCallback(PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation);
VOID HandlePostOperationCallback(PVOID RegistrationContext,
    POB_POST_OPERATION_INFORMATION OperationInformation);

VOID ClearEvents();
NTSTATUS ReadEvents(PIRP Irp);
NTSTATUS GetCount(PULONG count);
BOOLEAN IsCallerTrusted();

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    ULONG i;

    InitializeListHead(&g_EventListHead);
    KeInitializeSpinLock(&g_EventListLock);

    RtlInitUnicodeString(&g_DevName, L"\\Device\\IntegrityMonitor");
    RtlInitUnicodeString(&g_SymLink, L"\\DosDevices\\IntegrityMonitor");

    status = IoCreateDevice(DriverObject, 0, &g_DevName, FILE_DEVICE_UNKNOWN,
        0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: IoCreateDevice failed 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLink, &g_DevName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: IoCreateSymbolicLink failed 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DriverCreateClose;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: PsSetCreateProcessNotifyRoutineEx failed 0x%X\n", status);
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: PsSetCreateThreadNotifyRoutine failed 0x%X\n", status);
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: PsSetLoadImageNotifyRoutine failed 0x%X\n", status);
    }

    DECLARE_CONST_UNICODE_STRING(altitude, L"385200");

    OB_OPERATION_REGISTRATION opReg;
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = HandlePreOperationCallback;
    opReg.PostOperation = HandlePostOperationCallback;

    OB_CALLBACK_REGISTRATION cbReg;
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObCallbackRegistration);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IntegrityMonitor: ObRegisterCallbacks failed 0x%X\n", status);
        g_ObCallbackRegistration = NULL;
    }

    DbgPrint("IntegrityMonitor: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
    if (g_ObCallbackRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObCallbackRegistration);
        g_ObCallbackRegistration = NULL;
    }

    ClearEvents();

    IoDeleteSymbolicLink(&g_SymLink);
    IoDeleteDevice(g_DeviceObject);
    DbgPrint("IntegrityMonitor: Driver unloaded\n");
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (irpStack->MajorFunction == IRP_MJ_CREATE && !IsCallerTrusted()) {
        DbgPrint("IntegrityMonitor: Untrusted caller denied device open\n");
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl) {
    case IOCTL_INTEGRITY_GET_EVENTS:
        if (outLen < sizeof(INTEGRITY_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = ReadEvents(Irp);
        break;

    case IOCTL_INTEGRITY_CLEAR_EVENTS:
        if (!IsCallerTrusted()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (inLen != 0 || outLen != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ClearEvents();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_INTEGRITY_GET_COUNT: {
        if (outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG count;
        status = GetCount(&count);
        if (NT_SUCCESS(status)) {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = count;
            Irp->IoStatus.Information = sizeof(ULONG);
        }
        break;
    }

    case IOCTL_INTEGRITY_GET_VERSION: {
        if (outLen < 8) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        CHAR version[] = "2.0.0";
        ULONG len = (ULONG)strlen(version) + 1;
        if (outLen >= len) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, version, len);
            Irp->IoStatus.Information = len;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS AddEventToList(ULONG eventType, ULONG pid, const wchar_t* processName,
    const wchar_t* imagePath, ULONG targetPid, ULONG handleId, BOOLEAN isSuspicious) {
    KIRQL oldIrql;
    INTEGRITY_EVENT_ENTRY* entry;

    if (g_EventCount >= MAX_EVENTS) {
        return STATUS_BUFFER_OVERFLOW;
    }

    entry = (INTEGRITY_EVENT_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(INTEGRITY_EVENT_ENTRY), POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Event.EventType = eventType;
    entry->Event.Timestamp = KeQueryInterruptTime();
    entry->Event.ProcessId = pid;
    entry->Event.TargetProcessId = targetPid;
    entry->Event.HandleId = handleId;
    entry->Event.IsSuspicious = isSuspicious;

    RtlZeroMemory(entry->Event.ProcessName, sizeof(entry->Event.ProcessName));
    if (processName != NULL) {
        RtlStringCbCopyNW(entry->Event.ProcessName, sizeof(entry->Event.ProcessName),
            processName, MAX_PROCESS_NAME_COPY);
    }

    RtlZeroMemory(entry->Event.ImagePath, sizeof(entry->Event.ImagePath));
    if (imagePath != NULL) {
        RtlStringCbCopyNW(entry->Event.ImagePath, sizeof(entry->Event.ImagePath),
            imagePath, MAX_IMAGE_PATH_COPY);
    }

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    InsertTailList(&g_EventListHead, &entry->ListEntry);
    g_EventCount++;
    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    return STATUS_SUCCESS;
}

BOOLEAN IsCallerTrusted() {
    PEPROCESS currentProcess = IoGetCurrentProcess();
    if (currentProcess == NULL) {
        return FALSE;
    }
    HANDLE pid = PsGetProcessId(currentProcess);
    return (pid != NULL && HandleToULong(pid) == 4) ? TRUE : FALSE;
}

VOID ClearEvents() {
    KIRQL oldIrql;
    LIST_ENTRY* entry;
    LIST_ENTRY* temp;

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    for (entry = g_EventListHead.Flink; entry != &g_EventListHead; ) {
        temp = entry->Flink;
        RemoveEntryList(entry);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, INTEGRITY_EVENT_ENTRY, ListEntry), POOL_TAG);
        entry = temp;
    }
    g_EventCount = 0;
    KeReleaseSpinLock(&g_EventListLock, oldIrql);
}

NTSTATUS ReadEvents(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG offset = 0;
    KIRQL oldIrql;

    if (buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    while (!IsListEmpty(&g_EventListHead)) {
        LIST_ENTRY* entry = RemoveHeadList(&g_EventListHead);
        INTEGRITY_EVENT_ENTRY* evt = CONTAINING_RECORD(entry, INTEGRITY_EVENT_ENTRY, ListEntry);

        if (offset + sizeof(INTEGRITY_EVENT) <= outLen) {
            RtlCopyMemory(buffer + offset, &evt->Event, sizeof(INTEGRITY_EVENT));
            offset += sizeof(INTEGRITY_EVENT);
        } else {
            InsertHeadList(&g_EventListHead, entry);
            break;
        }

        ExFreePoolWithTag(evt, POOL_TAG);
        g_EventCount--;
    }
    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    Irp->IoStatus.Information = offset;
    return offset > 0 ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

NTSTATUS GetCount(PULONG count) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    *count = g_EventCount;
    KeReleaseSpinLock(&g_EventListLock, oldIrql);
    return STATUS_SUCCESS;
}

VOID ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    HANDLE pid = ProcessId;
    ULONG parentPid = 0;
    BOOLEAN isSuspicious = FALSE;

    if (CreateInfo != NULL) {
        parentPid = HandleToULong(CreateInfo->ParentProcessId);
    }

    wchar_t nameBuf[256] = { 0 };

    if (CreateInfo != NULL && CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL) {
        ULONG copyLen = min(CreateInfo->ImageFileName->Length, sizeof(nameBuf) - sizeof(wchar_t));
        __try {
            ProbeForRead(CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length, sizeof(wchar_t));
            RtlCopyMemory(nameBuf, CreateInfo->ImageFileName->Buffer, copyLen);
            nameBuf[copyLen / sizeof(wchar_t)] = L'\0';
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            RtlStringCbPrintfW(nameBuf, sizeof(nameBuf), L"PID:%lu", HandleToULong(pid));
        }
    } else {
        RtlStringCbPrintfW(nameBuf, sizeof(nameBuf), L"PID:%lu", HandleToULong(pid));
    }

    AddEventToList(CreateInfo != NULL ? EVENT_PROCESS_CREATED : EVENT_PROCESS_TERMINATED,
        HandleToULong(pid), nameBuf, NULL, parentPid, 0, isSuspicious);
}

VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    ULONG pid = HandleToULong(ProcessId);
    ULONG tid = HandleToULong(ThreadId);

    wchar_t nameBuf[64];
    RtlStringCbPrintfW(nameBuf, sizeof(nameBuf), L"TID:%lu", tid);

    AddEventToList(Create ? EVENT_THREAD_CREATED : EVENT_PROCESS_TERMINATED,
        pid, nameBuf, NULL, tid, 0, FALSE);
}

VOID ImageLoadNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ProcessId == NULL) {
        return;
    }

    ULONG pid = HandleToULong(ProcessId);
    BOOLEAN isSuspicious = FALSE;

    if (ImageInfo != NULL) {
        if (ImageInfo->ImageSignatureLevel == 0 &&
            FullImageName->Length > 0) {
            isSuspicious = TRUE;
        }
    }

    AddEventToList(EVENT_IMAGE_LOADED, pid, NULL, FullImageName->Buffer, 0, 0, isSuspicious);
}

OB_PREOP_CALLBACK_STATUS HandlePreOperationCallback(PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
    return OB_PREOP_SUCCESS;
}

VOID HandlePostOperationCallback(PVOID RegistrationContext,
    POB_POST_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (OperationInformation == NULL || OperationInformation->ObjectType != *PsProcessType) {
        return;
    }

    HANDLE targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
    if (targetPid == NULL) {
        return;
    }

    PEPROCESS callerProcess = IoGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(callerProcess);
    ACCESS_MASK desiredAccess = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;
    BOOLEAN isSuspicious = FALSE;

    if (desiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)) {
        if ((ULONG_PTR)targetPid != (ULONG_PTR)callerPid) {
            isSuspicious = TRUE;
        }
    }

    AddEventToList(EVENT_HANDLE_OPEN,
        HandleToULong(callerPid), NULL,
        NULL,
        HandleToULong(targetPid),
        (ULONG)desiredAccess,
        isSuspicious);
}
