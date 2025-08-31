#ifndef _INJECTOR_TEB_H_
#define _INJECTOR_TEB_H_

#include <Windows.h>
#include <winternl.h>

typedef struct _TEB32 {
    PVOID Reserved1[1];
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Reserved1x[9];
    PPEB  ProcessEnvironmentBlock;
    PVOID Reserved2[399];
    BYTE  Reserved3[1952];
    PVOID TlsSlots[64];
    BYTE  Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} TEB32, *PTEB32;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#endif // _INJECTOR_TEB_H_