#include "ntapi.h"

extern tmpl_NtQueryInformationThread fpNtQueryInformationThread;
extern tmpl_NtQueryInformationProcess fpNtQueryInformationProcess;

void resolve_native_apis() {
    HMODULE hModule;

    hModule = GetModuleHandleA("ntdll.dll");
    fpNtQueryInformationProcess = (tmpl_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
    fpNtQueryInformationThread = (tmpl_NtQueryInformationThread)GetProcAddress(hModule, "NtQueryInformationThread");
}