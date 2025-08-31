#ifndef _INJECTOR_THREAD_H_
#define _INJECTOR_THREAD_H_

#include "util.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>

#define OP_THREAD_SUSPEND 0
#define OP_THREAD_RESUME  1

std::vector<HANDLE> get_thread_handles(DWORD pid);
bool suspend_threads(std::vector<HANDLE> hThreads);
bool resume_threads(std::vector<HANDLE> hThreads);
bool close_handles(std::vector<HANDLE> handles);
// bool suspend_thread(DWORD tid);
// bool resume_thread(DWORD tid);
// bool operate_threads(DWORD pid, BYTE op);
// bool suspend_threads(DWORD pid);
// bool resume_threads(DWORD pid);

#endif // _INJECTOR_THREAD_H_