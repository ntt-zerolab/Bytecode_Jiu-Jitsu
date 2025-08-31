#ifndef _INJECTOR_NTAPI_H_
#define _INJECTOR_NTAPI_H_

#include <Windows.h>

typedef NTSTATUS (NTAPI* tmpl_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    UINT   ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* tmpl_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    UINT   ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength,
    PULONG ReturnLength
);

void resolve_native_apis();

#endif // _INJECTOR_NTAPI_H_