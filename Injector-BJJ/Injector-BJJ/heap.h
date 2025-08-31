#include <Windows.h>
#include <list>


#ifndef _WIN64
typedef struct _DEBUG_BUFFER {    //32-bit
HANDLE SectionHandle;
PVOID  SectionBase;
PVOID  RemoteSectionBase;
ULONG  SectionBaseDelta;
HANDLE  EventPairHandle;
ULONG  Unknown[2];
HANDLE  RemoteThreadHandle;
ULONG  InfoClassMask;
ULONG  SizeOfInfo;
ULONG  AllocatedSize;
ULONG  SectionSize;
PVOID  ModuleInformation;
PVOID  BackTraceInformation;
PVOID  HeapInformation;
PVOID  LockInformation;
PVOID  Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

typedef struct _DEBUG_HEAP_INFORMATION     //32-bit
{
ULONG Base; // 0x00
ULONG Flags; // 0x04
USHORT Granularity; // 0x08
USHORT Unknown; // 0x0A
ULONG Allocated; // 0x0C
ULONG Committed; // 0x10
ULONG TagCount; // 0x14
ULONG BlockCount; // 0x18
ULONG Reserved[7]; // 0x1C
PVOID Tags; // 0x38
PVOID Blocks; // 0x3C
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

struct HeapBlock
{
	PVOID dwAddress;
	DWORD dwSize;
	DWORD dwFlags;
	ULONG reserved;
};


#endif

#ifdef _WIN64

// DEBUG_BUFFER from: https://github.com/radareorg/radare2/blob/master/libr/include/heap/r_windows.h
typedef struct _DEBUG_BUFFER {
	HANDLE SectionHandle;
	PVOID SectionBase;
	PVOID RemoteSectionBase;
	WPARAM SectionBaseDelta;
	HANDLE EventPairHandle;
	HANDLE RemoteEventPairHandle;
	HANDLE RemoteProcessId;
	HANDLE RemoteThreadHandle;
	ULONG InfoClassMask;
	SIZE_T SizeOfInfo;
	SIZE_T AllocatedSize;
	SIZE_T SectionSize;
	PVOID ModuleInformation;
	PVOID BackTraceInformation;
	PVOID HeapInformation;
	PVOID LockInformation;
	PVOID SpecificHeap;
	HANDLE RemoteProcessHandle;
	PVOID VerifierOptions;
	PVOID ProcessHeap;
	HANDLE CriticalSectionHandle;
	HANDLE CriticalSectionOwnerThread;
	PVOID Reserved[4];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

// Patched version of DEBUG_HEAP_INFORMATION from: https://github.com/radareorg/radare2/blob/master/libr/include/heap/r_windows.h
typedef struct _DEBUG_HEAP_INFORMATION {
	PVOID Base;
	DWORD Flags;
	USHORT Granularity;
	USHORT CreatorBackTraceIndex;
	SIZE_T Allocated;
	SIZE_T Committed;
	DWORD TagCount;
	DWORD BlockCount;
	DWORD PseudoTagCount;
	DWORD PseudoTagGranularity;
	DWORD Reserved[5];
	PVOID Tags;
	PVOID Blocks;
	PVOID Reserved2;
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

#endif

typedef struct _HeapInfo {
    unsigned long id;
    unsigned long long base;
    bool default_flag;
	std::list<std::pair<ULONG_PTR, ULONG_PTR> > blocks;
} HeapInfo;

// From radare2
typedef struct _HeapBlockExtraInfo { // think of extra stuff to put here
	WPARAM heap;
	WPARAM segment;
	WPARAM unusedBytes;
	USHORT granularity;
} HeapBlockExtraInfo, * PHeapBlockExtraInfo;

typedef struct _HeapBlock {
	ULONG_PTR dwAddress;
	SIZE_T dwSize;
	DWORD dwFlags;
	SIZE_T index;
	PHeapBlockExtraInfo extraInfo;
} HeapBlock, * PHeapBlock;

typedef struct _HeapBlockBasicInfo {
	WPARAM size;
	WPARAM flags;
	WPARAM extra;
	WPARAM address;
} HeapBlockBasicInfo, * PHeapBlockBasicInfo;

#define SHIFT 16

#define EXTRA_FLAG			(1ULL << (sizeof (size_t) * 8 - 1))

// Until here, from radare2 

#define PDI_MODULES                       0x01
#define PDI_BACKTRACE                     0x02
#define PDI_HEAPS                         0x04
#define PDI_HEAP_TAGS                     0x08
#define PDI_HEAP_BLOCKS                   0x10
#define PDI_LOCKS                         0x20

extern "C"
__declspec(dllimport) NTSTATUS __stdcall RtlQueryProcessDebugInformation(IN ULONG  ProcessId, IN ULONG  DebugInfoClassMask, IN OUT PDEBUG_BUFFER  DebugBuffer);

extern "C"
__declspec(dllimport) PDEBUG_BUFFER __stdcall RtlCreateQueryDebugBuffer(IN ULONG  Size, IN BOOLEAN  EventPair);