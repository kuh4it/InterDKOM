//
// Inter
// -> Main.c
// 

#include <ntifs.h>
#include <ntddk.h>

#define IOCTL_CHECK_PML4_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PHYSICAL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_DTB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef unsigned char BYTE;

#pragma warning(disable : 4152)

extern NTKERNELAPI NTSTATUS ObCreateObject(
    IN KPROCESSOR_MODE      ObjectAttributesAccessMode OPTIONAL,
    IN POBJECT_TYPE         ObjectType,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN KPROCESSOR_MODE      AccessMode,
    IN PVOID                Reserved,
    IN ULONG                ObjectSizeToAllocate,
    IN ULONG                PagedPoolCharge OPTIONAL,
    IN ULONG                NonPagedPoolCharge OPTIONAL,
    OUT PVOID* Object
);

extern NTKERNELAPI NTSTATUS ObInsertObject(
    IN PVOID          Object,
    IN PACCESS_STATE  PassedAccessState OPTIONAL,
    IN ACCESS_MASK    DesiredAccess,
    IN ULONG          AdditionalReferences,
    OUT PVOID* ReferencedObject OPTIONAL,
    OUT PHANDLE       Handle
);

extern POBJECT_TYPE IoDriverObjectType; 

ULONG_PTR BruteForceDirectoryTableBase()
{
    ULONG_PTR directoryTableBase = 0;

    for (ULONG pml4Index = 0; pml4Index < 512; pml4Index++)
    {
        ULONG_PTR pml4Entry = __readcr3() & ~(0xFFF);
        pml4Entry |= (pml4Index * sizeof(ULONG_PTR));

        for (ULONG pdptIndex = 0; pdptIndex < 512; pdptIndex++)
        {
            ULONG_PTR pdptEntry = *(PULONG_PTR)pml4Entry;
            pdptEntry &= ~(0xFFF);
            pdptEntry |= (pdptIndex * sizeof(ULONG_PTR));

            for (ULONG pdIndex = 0; pdIndex < 512; pdIndex++)
            {
                ULONG_PTR pdEntry = *(PULONG_PTR)pdptEntry;
                pdEntry &= ~(0xFFF);
                pdEntry |= (pdIndex * sizeof(ULONG_PTR));

                for (ULONG ptIndex = 0; ptIndex < 512; ptIndex++)
                {
                    ULONG_PTR ptEntry = *(PULONG_PTR)pdEntry;
                    ptEntry &= ~(0xFFF);
                    ptEntry |= (ptIndex * sizeof(ULONG_PTR));

                    if (ptEntry & 0x1)
                    {
                        //
                        // Found a valid entry, set the DirectoryTableBase
                        //
                        directoryTableBase = ptEntry;
                        break;
                    }
                }

                if (directoryTableBase)
                    break;
            }

            if (directoryTableBase)
                break;
        }

        if (directoryTableBase)
            break;
    }

    return directoryTableBase;
}

NTSTATUS ReadPhysicalMemory(PVOID destination, PHYSICAL_ADDRESS source, SIZE_T size)
{
    PMDL memoryDescriptorList = MmCreateMdl(NULL, destination, size);
    if (!memoryDescriptorList)
        return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(memoryDescriptorList);
    memoryDescriptorList->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    PVOID mappedMemory = MmMapLockedPagesSpecifyCache(memoryDescriptorList, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedMemory)
    {
        IoFreeMdl(memoryDescriptorList);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(destination, mappedMemory, size);

    MmUnmapLockedPages(mappedMemory, memoryDescriptorList);
    IoFreeMdl(memoryDescriptorList);

    return STATUS_SUCCESS;
}

NTSTATUS WritePhysicalMemory(PHYSICAL_ADDRESS destination, PVOID source, SIZE_T size)
{
    PMDL memoryDescriptorList = MmCreateMdl(NULL, source, size);
    if (!memoryDescriptorList)
        return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(memoryDescriptorList);
    memoryDescriptorList->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    PVOID mappedMemory = MmMapLockedPagesSpecifyCache(memoryDescriptorList, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedMemory)
    {
        IoFreeMdl(memoryDescriptorList);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(mappedMemory, source, size);

    MmUnmapLockedPages(mappedMemory, memoryDescriptorList);
    IoFreeMdl(memoryDescriptorList);

    return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS DriverDispatchRoutine(
    _In_ PDEVICE_OBJECT,
    _In_ PIRP Irp
)
{
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
    ULONG Information = 0;
    UINT32 IoControlCode = 0;
    PIO_STACK_LOCATION IoStackLocation = nullptr;

    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    // METHOD_BUFFERED is being used; therefore, access the data via SystemBuffer.
    switch (IoControlCode)
    {
    case IOCTL_CHECK_PML4_OVERWRITE:
    {
        // DTB brute force to check if PML4 has been overwritten
        ULONG_PTR originalPML4 = __readcr3();
        ULONG_PTR bruteForcePML4 = BruteForceDirectoryTableBase();

        if (originalPML4 != bruteForcePML4)
        {
            // PML4 has been overwritten
            Status = STATUS_SUCCESS;
            Information = 1;
        }
        else
        {
            // PML4 is intact
            Status = STATUS_SUCCESS;
            Information = 0;
        }
        break;
    } 
    case IOCTL_READ_PHYSICAL_MEMORY:
    {
        //todo
        break;
    }

    case IOCTL_WRITE_PHYSICAL_MEMORY:
    {
        //todo
        break;
    }

    case IOCTL_CHECK_DTB:
    {
        //todo
        break;
    }
     
    default:
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    IofCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    return (STATUS_SUCCESS);
}

/* This will NOT work with manual mappers such as KDMapper, KDU, etc.. 
   To fix this, simply call IoCreateDriver with your new entry / driver initialization routine 
   
   https://gist.github.com/ultracage/635d4e2b67cc6fae196531e1c49d1185
*/

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING
)
{
    OBJECT_ATTRIBUTES objDriver;
    UNICODE_STRING    usFakeDriver;
    UNICODE_STRING    usFakeDevice;
    PDRIVER_OBJECT    pFakeDriver;
    PDEVICE_OBJECT    pFakeDevice;
    HANDLE            hNewDriver;
    PVOID             pFunctionPool;
    PVOID             pIofCompleteRequest;
    ULONG             ulObjectSize; 

    DriverObject->DriverUnload = &DriverUnload;
    RtlInitUnicodeString(&usFakeDriver, L"\\Driver\\RandomDriver");
    RtlInitUnicodeString(&usFakeDevice, L"\\Device\\RandomDevice");
    InitializeObjectAttributes(&objDriver, &usFakeDriver, OBJ_PERMANENT | OBJ_CASE_INSENSITIVE, 0, 0);
    ulObjectSize = (sizeof(DRIVER_OBJECT) + sizeof(DRIVER_EXTENSION)); // From WRK
    ObCreateObject(KernelMode, *(POBJECT_TYPE*)IoDriverObjectType, &objDriver, KernelMode, NULL, ulObjectSize, 0, 0, &pFakeDriver);
    ObInsertObject(pFakeDriver, 0, 1i64, 0, NULL, &hNewDriver);
    ZwClose(hNewDriver);
    /* 
      sub rsp, 0x28q
      mov rcx, rdx				; IRP
      xor edx, edx				; IO_NO_INCREMENT
      mov rax, 0xAAAAAAAAAAAAAAAA ; To be replaced with nt!IofCompleteRequest
      call rax
      add rsp, 0x28
      ret
    */
    BYTE bHandlerCode[26] = {
      0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xD1, 0x31, 0xD2, 0x48, 0xB8, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xFF, 0xD0, 0x48, 0x83, 0xC4,
      0x28, 0xC3
    };
    pFunctionPool = ExAllocatePool(NonPagedPool, 0x100);
    memset(pFunctionPool, 0x00, 0x100);
    pIofCompleteRequest = &IofCompleteRequest;
    memmove(&bHandlerCode[11], &pIofCompleteRequest, 8);
    memmove(pFunctionPool, &bHandlerCode, sizeof(bHandlerCode));

    /* 
    * To intercept execution and direct to hsr.ExecutionHandler in x86 architecture:
	memset(lpvBase, 0x0c, hsr.ReservedBaseSize);
	memset((PBYTE)lpvBase + hsr.ReservedBaseSize - 0x100 - 16, 0x90, 16); // nops for code alignment
	PBYTE pbHandlerCode = (PBYTE)lpvBase + hsr.ReservedBaseSize - 0x100;
	pbHandlerCode[0] = 0xb8; // mov eax, imm32/64
	*(size_t *)(pbHandlerCode + 1) = (size_t)hsr.ExecutionHandler;
	pbHandlerCode[1 + sizeof(size_t)] = 0xff; // call eax
	pbHandlerCode[2 + sizeof(size_t)] = 0xd0;
    
    Credits: crystalaep
    */

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        pFakeDriver->MajorFunction[i] = (PDRIVER_DISPATCH)pFunctionPool;
    }
    DbgPrint("pExePool: %I64X\n", pFunctionPool);
    pFakeDriver->Flags &= DO_BUFFERED_IO;
    pFakeDriver->FastIoDispatch = NULL;
    IoCreateDevice(pFakeDriver, 0, &usFakeDevice, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pFakeDevice);
    pFakeDevice->Flags = DO_DEVICE_HAS_NAME; 

    return (STATUS_SUCCESS);
}
