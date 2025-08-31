#include "thread.h"

std::vector<HANDLE> get_thread_handles(DWORD pid) {
    HANDLE hThread;
    std::vector<HANDLE> hThreads;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
    THREADENTRY32 te32; 
 
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
    if(hThreadSnap == INVALID_HANDLE_VALUE) 
        return hThreads; 
 
    te32.dwSize = sizeof(THREADENTRY32); 
 
    if(!Thread32First(hThreadSnap, &te32)) {
        log_err_msg();
        CloseHandle(hThreadSnap);
        return hThreads;
    }

    do { 
        if(te32.th32OwnerProcessID == pid) {
            hThread = OpenThread(THREAD_SUSPEND_RESUME, TRUE, te32.th32ThreadID);
            if (hThread) {
                hThreads.push_back(hThread);
            } else {
                log_err_msg();
            }
        }
    } while(Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return hThreads;
}

bool suspend_threads(std::vector<HANDLE> hThreads) {
    for (auto iter = hThreads.begin(); iter != hThreads.end(); iter++) {
        if (SuspendThread(*iter) < 0) {
            log_err_msg();
            return false;
        }
    }
    return true;
}

bool resume_threads(std::vector<HANDLE> hThreads) {
    for (auto iter = hThreads.begin(); iter != hThreads.end(); iter++) {
        if (ResumeThread(*iter) < 0) {
            log_err_msg();
            return false;
        }
    }
    return true;
}

bool close_handles(std::vector<HANDLE> handles) {
    for (auto iter = handles.begin(); iter != handles.end(); iter++) {
        if (CloseHandle(*iter) == 0) {
            log_err_msg();
            return false;
        }
    }
    return true;
}