#ifndef INJECTOR_INJECTOR_H_
#define INJECTOR_INJECTOR_H_

#include "payload.h"
#include "common.h"
#include "config.h"
#include "inject.h"
#include "memory.h"
#include "ntapi.h"
#include "peb.h"
#include "search.h"
#include "thread.h"
#include "util.h"
#include <argparse/argparse.hpp>
#include <Windows.h>
#include <stdio.h>
#include <winuser.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <regex>
#include <list>
#include <utility>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <algorithm>

#define DPSAPI_VERSION 1
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "User32.lib")

typedef struct _ReplacementContent {
    BYTE *pattern;
    SIZE_T pattern_len;
    BYTE *bytes;
    SIZE_T bytes_len;
} ReplacementContent;

bool resume_thread(PROCESS_INFORMATION *pi);

#endif  // INJECTOR_INJECTOR_H_