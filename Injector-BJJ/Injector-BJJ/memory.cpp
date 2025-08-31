#include "memory.h"

extern std::ostream *out;
extern tmpl_NtQueryInformationThread fpNtQueryInformationThread;
extern tmpl_NtQueryInformationProcess fpNtQueryInformationProcess;

int stack_dump_count = 0;
int heap_dump_count = 0;


static bool GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb)
{
    PHeapBlockBasicInfo block;

    hb->index = 0;
    // hb->reserved = 0;
    hb->dwAddress = 0;
    hb->dwFlags = 0;
    hb->extraInfo = NULL;

    block = (PHeapBlockBasicInfo)heapInfo->Blocks;
    if (!block) {
        return false;
    }

    SIZE_T index = hb->index;
    do {
        if (index > heapInfo->BlockCount) {
            return false;
        }
        hb->dwAddress = block[index].address;
        hb->dwSize = block->size;
        if (block[index].extra & EXTRA_FLAG) {
            PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
            hb->dwSize -= extra->unusedBytes;
            hb->extraInfo = extra;
            hb->dwAddress = (WPARAM)hb->dwAddress + extra->granularity;
        }
        else {
            hb->dwAddress = (WPARAM)hb->dwAddress + heapInfo->Granularity;
            hb->extraInfo = NULL;
        }
        if (hb->dwSize >= 0x10000) hb->dwSize -= 0x1010;

        *out << "Address: 0x" << std::hex << hb->dwAddress << std::endl;
        *out << "Size: 0x" << std::hex << hb->dwSize << std::endl;
        *out << "Index: " << std::dec << hb->index << std::endl;
        index++;
    } while (block[index].flags & 2);

    WPARAM flags = block[hb->index].flags;

    if ((flags & 0xF1) != 0 || (flags & 0x0200) != 0)
        hb->dwFlags = LF32_FIXED;
    else if ((flags & 0x20) != 0)
        hb->dwFlags = LF32_MOVEABLE;
    else if ((flags & 0x0100) != 0)
        hb->dwFlags = LF32_FREE;

    hb->dwFlags |= ((flags) >> SHIFT) << SHIFT;
    hb->index = index;

    return TRUE;
}

static bool GetNextHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb)
{
    PHeapBlockBasicInfo block;

    block = (PHeapBlockBasicInfo)heapInfo->Blocks;

    SIZE_T index = hb->index;

    if (index >= heapInfo->BlockCount) {
        return false;
    }

    *out << "Block count: " << std::dec << heapInfo->BlockCount << std::endl;

    if (block[index].flags & 2) {
        do {
            if (index >= heapInfo->BlockCount) {
                return false;
            }

            hb->dwAddress = block[index].address + heapInfo->Granularity;
            *out << "Address(in): " << std::hex << hb->dwAddress << std::endl;

            index++;
            hb->dwSize = block->size;
            *out << "Size(in): " << std::hex << hb->dwSize << std::endl;
        } while (block[index].flags & 2);
        hb->index = index;
    }
    else {
        hb->dwSize = block[index].size;
        if (block[index].extra & EXTRA_FLAG) {
            PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
            hb->extraInfo = extra;
            hb->dwSize -= extra->unusedBytes;
            hb->dwAddress = block[index].address + extra->granularity;
        }
        else {
            hb->extraInfo = NULL;
            hb->dwAddress = (WPARAM)hb->dwAddress + hb->dwSize;
        }
        hb->index++;
    }
    if (hb->dwSize >= 0x10000) hb->dwSize -= 0x1010;

    *out << "Address: 0x" << std::hex << hb->dwAddress << std::endl;
    *out << "Size: 0x" << std::hex << hb->dwSize << std::endl;
    *out << "Index: " << std::dec << hb->index << std::endl;

    WPARAM flags;
    if (block[index].extra & EXTRA_FLAG) {
        flags = block[index].flags;
    }
    else {
        flags = (USHORT)block[index].flags;
    }

    if ((flags & 0xF1) != 0 || (flags & 0x0200) != 0)
        hb->dwFlags = LF32_FIXED;
    else if ((flags & 0x20) != 0)
        hb->dwFlags = LF32_MOVEABLE;
    else if ((flags & 0x0100) != 0)
        hb->dwFlags = LF32_FREE;

    return TRUE;
}

BinaryContent get_heap_block(HANDLE hProcess, LPVOID heap_block_addr, LONGLONG heap_block_size) {
    BOOL result;
    BYTE *bytes;
    SIZE_T read_len;
    DWORD err;

    if (heap_block_size == 0) heap_block_size = 0x1000;

    bytes = new BYTE[heap_block_size];
    
    result = ReadProcessMemory(
        hProcess,
        heap_block_addr,
        bytes,
        heap_block_size,
        &read_len
    );

    if (result == 0) {
        *out << "Error: ReadProcessMemory of 0x"
             << std::hex
             << heap_block_size
             << " bytes to 0x"
             << heap_block_addr
             << " failed."
             << " 0x"
             << read_len
             << " bytes read."
             << std::endl;
        log_err_msg();
    }
    else {
        *out << "OK: ReadProcessMemory of 0x"
             << std::hex
             << heap_block_size
             << " bytes to 0x"
             << heap_block_addr
             << " 0x"
             << read_len
             << " bytes read."
             << std::endl;
    }

    heap_dump_count++;

    return {heap_block_addr, bytes, read_len};
}

std::list<BinaryContent> get_heap_contents(HANDLE hProcess, std::list<HeapInfo> heaps) {
    std::list<BinaryContent> contents;
    BinaryContent content;

    for (auto heaps_iter = heaps.begin(); heaps_iter != heaps.end(); heaps_iter++) {
        for (auto blocks_iter = heaps_iter->blocks.begin(); blocks_iter != heaps_iter->blocks.end(); blocks_iter++) {
            auto [start_addr, end_addr] = *blocks_iter;
            content = get_heap_block(hProcess, (LPVOID)start_addr, end_addr - start_addr);
            contents.push_back(content);
        }
    }

    return contents;
}

void log_heap_info(std::list<HeapInfo> heaps) {
    for (auto heaps_iter = heaps.begin(); heaps_iter != heaps.end(); heaps_iter++) {
        for (auto blocks_iter = heaps_iter->blocks.begin(); blocks_iter != heaps_iter->blocks.end(); blocks_iter++) {
            auto [sa, ea] = *blocks_iter;
            *out << "trace: heap, start addr: 0x"
                 << (LPVOID)sa
                 << ", end addr: 0x"
                 << (LPVOID)ea
                 << std::endl;
        }
    }
}

std::list<HeapInfo> GetListOfHeaps(DWORD pid, DWORD *current_heap_index) {
    std::list<HeapInfo> heaps;
    DWORD heap_index;

    heap_index = *current_heap_index;

    HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    PROCESS_BASIC_INFORMATION pib;
    if (fpNtQueryInformationProcess(ph, ProcessBasicInformation, &pib, sizeof(pib), NULL)) {
        *out << "Error: NtQueryInformationProcess" << std::endl;
        return heaps;
    }
    PEB peb;
    ReadProcessMemory(ph, pib.PebBaseAddress, &peb, sizeof(PEB), NULL);
    PVOID heapAddress;
    PVOID* processHeaps;
    ULONG numberOfHeaps;

    processHeaps = *((PVOID**)(((uint8_t*)&peb) + 0xF0));
    numberOfHeaps = *((ULONG*)(((uint8_t *)&peb) + 0xE8));

    *out << "Number of heaps from PEB: "
         << numberOfHeaps
         << std::endl;
    
    HeapInfo heap;
    
    do {
        heap_index++;
        ReadProcessMemory(ph, processHeaps, &heapAddress, sizeof(PVOID), NULL);
        heap.id = heap_index;
        heap.base = (uint64_t)heapAddress;
        heaps.push_back(heap);
        *out << "Heap base address from PEB: 0x"
             << heapAddress
             << std::endl;
        processHeaps += 1;
    } while (--numberOfHeaps);

    *current_heap_index = heap_index;

    return heaps;
}

std::list<HeapInfo> get_heap_info(DWORD pid) {
    HANDLE hHeapSnap;
    std::list<HeapInfo> heaps;
    PDEBUG_BUFFER dbg_buf;
    unsigned long global_heap_index;

    hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
    if (hHeapSnap != INVALID_HANDLE_VALUE) {
        dbg_buf = RtlCreateQueryDebugBuffer(0, FALSE);
        RtlQueryProcessDebugInformation(pid, PDI_HEAPS | PDI_HEAP_BLOCKS, dbg_buf);

#ifdef _WIN64
        DWORD64 heap_node_count = dbg_buf->HeapInformation ? *PDWORD64(dbg_buf->HeapInformation) : 0;
        PDEBUG_HEAP_INFORMATION heap_info = PDEBUG_HEAP_INFORMATION(PDWORD64(dbg_buf->HeapInformation) + 1);	
#elif _WIN32
        DWORD heap_node_count = dbg_buf->HeapInformation ? *PULONG(dbg_buf->HeapInformation) : 0;		
        PDEBUG_HEAP_INFORMATION heap_info = PDEBUG_HEAP_INFORMATION(PULONG(dbg_buf->HeapInformation) + 1);		
#endif
        *out << "Number of heaps from RtlQueryProcessDebugInformation: "
             << heap_node_count
             << std::endl;

        *out << "Dump of heap_info:" << std::endl;
        PBYTE heap_info_dump = (PBYTE)heap_info;
        for (int i = 0; i < 30; i++) {
            for (int j = 0; j < 0x10; j++) {
                *out << std::hex << std::setfill('0') << std::setw(2)
                     << (int)*heap_info_dump
                     << " ";
                heap_info_dump++;
            }
            *out << std::endl;
        }
        *out << std::endl;

        *out << "Size of DEBUG_HEAP_INFORMATION: "
             << std::dec
             << sizeof(DEBUG_HEAP_INFORMATION)
             << std::endl;

        for (unsigned long heap_index = 0; heap_index < heap_node_count; heap_index++) {
            HeapInfo heap;
            heap.id = heap_index;
            heap.base = (uint64_t)heap_info[heap_index].Base;
            heap.default_flag = heap_info[heap_index].Flags & HF32_DEFAULT;

            *out << "Heap base address from RtlQueryProcessDebugInformation: 0x" 
                 << (LPVOID)heap.base
                 << std::endl;
            
            HeapBlock heap_block = { 0, 0, 0, 0 };
            memset(&heap_block, 0, sizeof(heap_block));

            if (GetFirstHeapBlock(&heap_info[heap_index], &heap_block)){
                do {
                    ULONG_PTR start_addr = (ULONG_PTR)heap_block.dwAddress;
                    ULONG_PTR end_addr = (ULONG_PTR)start_addr + heap_block.dwSize;
                    heap.blocks.push_back(std::make_pair(start_addr, end_addr));
                } while (GetNextHeapBlock(&heap_info[heap_index], &heap_block));
            }
            heaps.push_back(heap);

            global_heap_index = heap_index;
        }
    }
    else {
        std::cout << "Error: CreateToolhelp32Snapshot" << std::endl;
    }

    CloseHandle(hHeapSnap);
    return heaps;
}

void log_memory_basic_info(MEMORY_BASIC_INFORMATION mbi) {
    *out << "trace: memory basic info, base address: 0x"
         << mbi.BaseAddress
         << ", region size: 0x"
         << std::hex << std::setfill('0') << std::setw(8)
         << mbi.RegionSize
         << ", state: 0x"
         << std::hex << std::setfill('0') << std::setw(4)
         << mbi.State
         << ", protect: 0x"
         << std::hex << std::setfill('0') << std::setw(4)
         << mbi.Protect
         << std::endl;
}

BinaryContent get_stack_content(HANDLE hProcess, LPVOID stack_limit, SIZE_T stack_size) {
    BOOL result;
    BYTE *bytes;
    SIZE_T read_len;
    DWORD err;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T len;

    bytes = new BYTE[stack_size];

    len = VirtualQueryEx(hProcess,
        stack_limit,
        &mbi,
        0x1000);

    if (len == 0) {
        *out << "Error: VirtualQueryEx, Stack address: 0x" << stack_limit << std::endl;
        log_err_msg();
    }

    log_memory_basic_info(mbi);

    result = ReadProcessMemory(
        hProcess,
        stack_limit,
        bytes,
        stack_size,
        &read_len
    );

    *out << "Stack address: 0x"
         << stack_limit
         << ", Read len: "
         << read_len
         << std::endl;

    if (result == 0) {
        *out << "Error: ReadProcessMemory, Stack address: 0x" << stack_limit << std::endl;
        log_err_msg();
    }

    stack_dump_count++;

    return {stack_limit, bytes, stack_size};
}

std::list<BinaryContent> get_stack_contents(HANDLE hProcess, std::list<StackInfo> stacks) {
    std::list<BinaryContent> contents;
    BinaryContent content;

    for (auto iter = stacks.begin(); iter != stacks.end(); iter++) {
        content = get_stack_content(hProcess, iter->limit, iter->size);
        contents.push_back(content);
    }

    return contents;
}

void log_stack_info(std::list<StackInfo> stacks) {
    for (auto& stack : stacks) {
        *out << "trace: stack, base: 0x"
            << stack.base
            << ", limit: 0x"
            << stack.limit
            << ", size: 0x"
            << std::hex << std::setfill('0') << std::setw(4)
            << stack.size
            << std::endl;
    }
}

std::list<StackInfo> get_stack_info(DWORD pid, HANDLE hProcess) {
    TEB32 teb;
    THREAD_BASIC_INFORMATION tbi;
    ULONG len;
    SIZE_T read_len;
    HANDLE hThread;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
    THREADENTRY32 te32;
    NTSTATUS status;
    std::list<StackInfo> stacks;

    THREADINFOCLASS ThreadBasicInformation = static_cast<THREADINFOCLASS>(0);

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
    if(hThreadSnap == INVALID_HANDLE_VALUE) {
        log_err_msg();
        return stacks; 
    }
 
    te32.dwSize = sizeof(THREADENTRY32); 
 
    if(!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return stacks;
    }

    do { 
        if(te32.th32OwnerProcessID == pid) {
            hThread = OpenThread(THREAD_ALL_ACCESS,
                TRUE,
                te32.th32ThreadID);
            status = fpNtQueryInformationThread(hThread,
                ThreadBasicInformation,
                &tbi,
                sizeof(tbi),
                &len
            );

            ReadProcessMemory(
                hProcess,
                tbi.TebBaseAddress,
                &teb,
                sizeof(teb),
                &read_len
            );

            StackInfo stack;
            stack.base = teb.StackBase;
            stack.limit = teb.StackLimit;
            stack.size = (int64_t)teb.StackBase - (int64_t)teb.StackLimit;
            stacks.push_back(stack);
        }
    } while(Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);

    return stacks;
}

void dump_memory(BYTE *content, SIZE_T content_len, char *dir_name, char *prefix, LPVOID base_addr, char *extension) {
    FILE *fp;
    errno_t err;
    char *file_name;
    const SIZE_T len = 256;

    file_name = new char[len];
    ZeroMemory(file_name, len);
    _snprintf_s(file_name, len, _TRUNCATE, "%s\\%s%llx%s", dir_name, prefix, (ULONGLONG)base_addr, extension);
    err = fopen_s(&fp, file_name, "wb");
    if (err) {
        std::cout << "Error: fopen_s" << std::endl;
        std::cout << err << std::endl;
    }
    fwrite(content, content_len, 1, fp);
    fclose(fp);
    delete[] file_name;
}
