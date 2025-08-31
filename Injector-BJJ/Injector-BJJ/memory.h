#ifndef _INJECTOR_MEMORY_H_
#define _INJECTOR_MEMORY_H_

#include <Windows.h>
#include "ntapi.h"
#include "stack.h"
#include "heap.h"
#include "teb.h"
#include "util.h"
#include <iomanip>
#include <iostream>
#include <list>
#include <tlhelp32.h>
#include <winternl.h>

typedef struct _BinaryContent {
    LPVOID addr;
    BYTE *bytes;
    SIZE_T len;
} BinaryContent;

void log_err_msg();
void log_heap_info(std::list<HeapInfo> heaps);
void log_stack_info(std::list<StackInfo> stacks);
void log_memory_basic_info(MEMORY_BASIC_INFORMATION mbi);
void dump_memory(BYTE *content, SIZE_T content_len, char *dir_name, char *prefix, LPVOID base_addr, char *extension);
static bool GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb);
static bool GetNextHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb);
std::list<HeapInfo> get_heap_info(DWORD pid);
std::list<StackInfo> get_stack_info(DWORD pid, HANDLE hProcess);
BinaryContent get_heap_content(HANDLE hProcess, LPVOID heap_block_addr, DWORD heap_block_size);
std::list<BinaryContent> get_heap_contents(HANDLE hProcess, std::list<HeapInfo> heaps);
BinaryContent get_stack_content(HANDLE hProcess, LPVOID stack_limit, DWORD stack_size);
std::list<BinaryContent> get_stack_contents(HANDLE hProcess, std::list<StackInfo> stacks);

#endif // _INJECTOR_MEMORY_H_