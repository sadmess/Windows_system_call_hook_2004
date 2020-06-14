
#include "hook.h"

VOID NTAPI KhpPlantHookCallbackFunction(ULONG64 addr)
{
	KhpHookCallback = NTOS_OFFSET(0xCFBBB0, ULONG64);

	DbgPrint("Hook callback %llx", KhpHookCallback);

	*KhpHookCallback = addr;
}

BOOLEAN DataCompare(const UCHAR* pData, const UCHAR* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPatternA(UINT64 dwAddress, UINT64 dwLen, UCHAR* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (DataCompare((UCHAR*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

VOID NTAPI KhpEnableDisableWriteProtection(BOOLEAN disable)
{
	ULONG64 cr0 = KhpGetCr0();

	if (disable)
		cr0 &= ~0x10000;
	else
		cr0 |= 0x10000;

	KhpSetCr0(cr0);
}

PVOID GetSystemRoutineAddress(LPCWSTR name)
{
	UNICODE_STRING unicodeName;
	RtlInitUnicodeString(&unicodeName, name);
	return MmGetSystemRoutineAddress(&unicodeName);
}

uintptr_t get_kernel_address(LPCWSTR name, size_t* size) {
	PLIST_ENTRY loadedModuleList = (PLIST_ENTRY)(GetSystemRoutineAddress(L"PsLoadedModuleList"));
	DbgPrint("loadedModuleList: %I64X\n", loadedModuleList);
	if (!loadedModuleList)
		return NULL;

	__try
	{
		for (PLIST_ENTRY link = loadedModuleList->Flink; link != loadedModuleList; link = link->Flink)
		{
			LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (_wcsicmp(name, entry->BaseDllName.Buffer) == 0)
			{
				DbgPrint("BaseDllName: %ws\n", entry->BaseDllName.Buffer);
				DbgPrint("DllBase: %I64X\n", entry->DllBase);
				*size = entry->SizeOfImage;
				return entry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

VOID findoffset() {

	size_t size = 0;
	UINT64 ntoskrnlBase = get_kernel_address(L"ntoskrnl.exe", &size);

	KhpKeSetSystemServiceCallbackOffset = FindPatternA((UINT64)ntoskrnlBase, (UINT64)size, (UCHAR*)"\x48\x8d\x05\xCC\xCC\xCC\xCC\x4d\xCC\xCC\x49\x83\xe2\xf8", "xxx????x??xxxx") - 0x2f - ntoskrnlBase;

	callbackAllowCheckOffset = FindPatternA((UINT64)ntoskrnlBase, (UINT64)size, (UCHAR*)"\x0f\x84\xCC\xCC\xCC\xCC\x4c\x8b\xCC\xCC\xCC\xCC\xCC\x41\xf6\xCC\xCC\xCC\x49\x8b\x1a", "xx????xx?????xx???xxx") - ntoskrnlBase;

	enableCheckLogicOffset = callbackAllowCheckOffset + 0x6c;

	//callbackAddressLoadOffset = enableCheckLogicOffset+0x9; //1903-1909

	callbackAddressLoadOffset = enableCheckLogicOffset + 0x9 + 0x7; //2004
}
BOOLEAN NTAPI KhpLockCodeMemory(ULONG64 addr, ULONG length, PSYSTEM_MEMORY sysMemInfo)
{
	PUCHAR buffer;
	PMDL mdl = NULL;

	RtlZeroMemory(sysMemInfo, sizeof(SYSTEM_MEMORY));

	mdl = IoAllocateMdl((PVOID)addr, length, FALSE, FALSE, NULL);

	if (!mdl)
	{
		return FALSE;
	}

	/*__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DLOG("lock page error");
		return FALSE;
	}*/

	buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

	if (!buffer)
	{
		return FALSE;
	}

	if (MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS)
	{
		return FALSE;
	}

	sysMemInfo->memoryBuffer = buffer;
	sysMemInfo->addr = addr;
	sysMemInfo->length = length;
	sysMemInfo->mdl = mdl;

	return TRUE;
}

BOOLEAN NTAPI KhpUnlockCodeMemory(PSYSTEM_MEMORY memInfo)
{
	MmProtectMdlSystemAddress(memInfo->mdl, PAGE_EXECUTE_READ);

	/*__try
	{
		MmUnlockPages(memInfo->mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DLOG("unlock error");
		return FALSE;
	}*/

	IoFreeMdl(memInfo->mdl);

	RtlZeroMemory(memInfo, sizeof(SYSTEM_MEMORY));

	return TRUE;
}
BOOLEAN NTAPI KhpPatchKiTrackSystemCallEntry()
{
	SYSTEM_MEMORY meminfo;


	const ULONG blockSize = ALIGN(callbackAddressLoadOffset - callbackAllowCheckOffset + 32, 8);

	//UCHAR oldOffset[] = { 0x7A, 0x20, 0xCF, 0xFF };

	PUCHAR beginAddr = NTOS_OFFSET(callbackAllowCheckOffset, UCHAR);

	if (!KhpLockCodeMemory((ULONG64)beginAddr, blockSize, &meminfo))
	{
		return FALSE;
	}


	*NTOS_OFFSET(enableCheckLogicOffset, UCHAR) = 0x75;
	*(NTOS_OFFSET(callbackAddressLoadOffset, UCHAR) + 3) += 0x40;
	*(NTOS_OFFSET(callbackAllowCheckOffset, UCHAR) + 1) = 0x85;

	KhpUnlockCodeMemory(&meminfo);

	return TRUE;
}

BOOLEAN NTAPI KhpInit()
{
	ULONG64 ntosBase;

	size_t size = 0;
	ntosBase = get_kernel_address(L"ntoskrnl.exe", &size);
	KhpNtosBase = ntosBase;
	if (!ntosBase)
		return FALSE;

	KhpOriginalNtClose = (PNTCLOSEPTR)NtTerminateProcessOffset;
	KeSetSystemServiceCallback = (PKESETSYSTEMSERVICECALLBACKPTR)(ntosBase + KhpKeSetSystemServiceCallbackOffset);

	DbgPrint("KeSetSystemServiceCallback is at: %p", KhpOriginalNtClose);
	//DLOG("Original NtClose: %p", KhpOriginalNtClose);

	return TRUE;
}

BOOLEAN NTAPI KhInitiazeHookSystem() {
	BOOLEAN status = FALSE;

	if (!KhpInit())
		return FALSE;

	KhpPlantHookCallbackFunction((ULONG64)KhpHookHandler);

	KhpEnableDisableWriteProtection(TRUE);

	status = KhpPatchKiTrackSystemCallEntry();

	KhpEnableDisableWriteProtection(FALSE);

	if (status)
		DbgPrint("Hook initialized!");

	return status;
}

BOOLEAN NTAPI KhpReverseCallbackSetLogic()
{
	BOOLEAN status = FALSE;
	SYSTEM_MEMORY sysMemory;
	const ULONG routineOffset = 0x29;

	PUCHAR paddr = NTOS_OFFSET(KhpKeSetSystemServiceCallbackOffset + routineOffset, UCHAR);

	if (!KhpLockCodeMemory((ULONG64)paddr, sizeof(ULONG64), &sysMemory))
	{
		return FALSE;
	}
	PUCHAR inst = sysMemory.memoryBuffer;
	if (*paddr == 0x74)
	{
		*paddr = 0x75;
		status = TRUE;
	}
	else if (*paddr == 0x75)
	{
		*paddr = 0x74;
		status = FALSE;
	}

	KhpUnlockCodeMemory(&sysMemory);

	return status;
}

NTSTATUS NTAPI KhSetResetHook(BOOLEAN set)
{
	PULONG64 callback = NULL;
	NTSTATUS ntstatus = STATUS_SUCCESS;
	BOOLEAN status = FALSE;

	KhpEnableDisableWriteProtection(TRUE);

	if (set)
	{
		callback = KhpHookCallback;
		status = KhpReverseCallbackSetLogic();

		if (!status)
		{
			ntstatus = STATUS_UNSUCCESSFUL;
			goto exit;
		}
	}

	if (!NT_SUCCESS(KeSetSystemServiceCallback("DisplayString", TRUE, (ULONG64)callback, NULL)))
	{
		ntstatus = STATUS_UNSUCCESSFUL;
		goto exit;
	}

exit:

	if (status)
		KhpReverseCallbackSetLogic();
	KhpEnableDisableWriteProtection(FALSE);

	return ntstatus;
}

#pragma optimize("",off)

NTSTATUS NTAPI KhpHooked_NtDisplayString()
{
	DbgPrint("HOOK SUCCESS\n");
	return STATUS_SUCCESS;
}
#pragma optimize("",on)
VOID testunload() {
}

NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{
	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)testunload;
	findoffset();
	if (!KhInitiazeHookSystem())
		return STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(KhSetResetHook(TRUE)))
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


NTKERNELAPI NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName, OPTIONAL IN PDRIVER_INITIALIZE InitializationFunction);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath) {
	DbgPrint("> begin\n");
	UNICODE_STRING drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\MyDriver1");

	return IoCreateDriver(&drv_name, &DriverInitialize);
}
