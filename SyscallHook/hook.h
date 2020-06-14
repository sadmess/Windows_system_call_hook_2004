#pragma once
#include <ntifs.h>
#include <ntstatus.h>
#include <minwindef.h>
#include <ntimage.h>
#include <intrin.h>

#define DELAY_ONE_MICROSECOND         ( -10 )
#define DELAY_ONE_MILLISECOND        ( DELAY_ONE_MICROSECOND * 1000 )
#define NTOS_OFFSET(off, type) ((type *)(KhpNtosBase + (off)))
#define MAPPED_OFFSET_MEM(offset, mem) ((PUCHAR)KhpMapKernelOffsetForLockedPage((offset),mem))
#define ALIGN(x,align) ( ( ( (x) / (align) ) + 1 ) * align )
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64	InLoadOrderLinks;
	LIST_ENTRY64	InMemoryOrderLinks;
	LIST_ENTRY64	InInitializationOrderLinks;
	UINT64			DllBase;
	UINT64			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	USHORT			LoadCount;
	USHORT			TlsIndex;
	PVOID			SectionPointer;
	ULONG			CheckSum;
	PVOID			LoadedImports;
	PVOID			EntryPointActivationContext;
	PVOID			PatchInformation;
	LIST_ENTRY64	ForwarderLinks;
	LIST_ENTRY64	ServiceTagLinks;
	LIST_ENTRY64	StaticLinks;
	PVOID			ContextInformation;
	ULONG64			OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct __SYSTEM_MEMORY
{
	PMDL        mdl;
	ULONG64     addr;
	PUCHAR      memoryBuffer;
	ULONG       length;
}SYSTEM_MEMORY, * PSYSTEM_MEMORY;

typedef NTSTATUS(NTAPI* PKESETSYSTEMSERVICECALLBACKPTR)(
	PCHAR systemCallString,
	BOOLEAN isEntry,
	ULONG64 callback,
	PVOID callbackArg
	);

typedef NTSTATUS(NTAPI* PNTCLOSEPTR)();


extern ULONG64 NTAPI KhpGetCr0();

extern void NTAPI KhpSetCr0(ULONG64 value);

extern NTSTATUS NTAPI KhpHookHandler();

ULONG64 KhpNtosBase = 0;


ULONG64 NtTerminateProcessOffset;
ULONG64 KhpKeSetSystemServiceCallbackOffset;
ULONG callbackAllowCheckOffset;
ULONG enableCheckLogicOffset;
ULONG callbackAddressLoadOffset;
PNTCLOSEPTR KhpOriginalNtClose = 0;

PKESETSYSTEMSERVICECALLBACKPTR KeSetSystemServiceCallback = NULL;

PULONG64 KhpHookCallback = NULL;

VOID KeSleep(IN LONG lSeccond)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= lSeccond;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}
