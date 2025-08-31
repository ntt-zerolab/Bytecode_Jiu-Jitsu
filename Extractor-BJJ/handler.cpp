#include "handler.h"

extern std::string output_payload_file_name;
extern UINT8 output_payload_file_type;
extern unordered_map<ADDRINT, UINT32> heap_allocations;
extern PIN_MUTEX heap_mutex;
size_t allocated_bytes;

VOID hdlr_interp_func_before(CONTEXT* ctxt, ADDRINT* stack_ptr, Config* config) {
    Payload payload;
    ADDRINT management_structure_addr;
    vector<UINT8> bytecode_bytes;
    vector<UINT8> symbol_table_bytes;

    cout << "[+] Finding management structure address ..." << endl;
    management_structure_addr = extract_management_structure_addr(ctxt, stack_ptr, config->management_structure_index);
    cout << "[+] Found management structure address: "
        << (void*)management_structure_addr
        << endl;

    payload.bytecode = extract_bytecode(management_structure_addr, config->bytecode);
    for (auto it = config->symbol_tables.begin(); it != config->symbol_tables.end(); it++)
      payload.symbol_tables.push_back(extract_symbol_table(management_structure_addr, *it));

  if (output_payload_file_type == kPayloadFileTypeJson) {
    save_payload_to_json(payload, output_payload_file_name);
  }
  else if (output_payload_file_type == kPayloadFileTypeCHeader) {
    save_payload_to_header(payload, output_payload_file_name);
  }

  // wait_for_debugger_attach(30);
}

VOID hdlr_CoTaskMemAlloc_before(CHAR *name, size_t bytes) {
  allocated_bytes = bytes;
}

VOID hdlr_CoTaskMemAlloc_after(CHAR *name, ADDRINT allocated_addr) {
  if (allocated_addr) {
    PIN_MutexLock(&heap_mutex);
    heap_allocations[allocated_addr] = allocated_bytes;
    PIN_MutexUnlock(&heap_mutex);

    std::cout << "[+] CoTaskMemAlloc called: Address="
              << (VOID *)allocated_addr
              << ", Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  } else {
    std::cerr << "[+] CoTaksMemAlloc failed for Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  }
}

VOID hdlr_GlobalAlloc_before(CHAR *name, size_t bytes) {
  allocated_bytes = bytes;
}

VOID hdlr_GlobalAlloc_after(CHAR *name, ADDRINT allocated_addr) {
  // TODO: Parse DECLSPEC_ALLOCATOR HGLOBAL
  if (allocated_addr) {
    PIN_MutexLock(&heap_mutex);
    heap_allocations[allocated_addr] = allocated_bytes;
    PIN_MutexUnlock(&heap_mutex);

    std::cout << "[+] GlobalAlloc called: Address="
              << (VOID *)allocated_addr
              << ", Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  } else {
    std::cerr << "[+] GlobalAlloc failed for Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  }
}

VOID hdlr_LocalAlloc_before(CHAR *name, size_t bytes) {
  allocated_bytes = bytes;
}

VOID hdlr_LocalAlloc_after(CHAR *name, ADDRINT allocated_addr) {
  // TODO: Parse DECLSPEC_ALLOCATOR HGLOBAL
  if (allocated_addr) {
    PIN_MutexLock(&heap_mutex);
    heap_allocations[allocated_addr] = allocated_bytes;
    PIN_MutexUnlock(&heap_mutex);

    std::cout << "[+] LocalAlloc called: Address="
              << (VOID *)allocated_addr
              << ", Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  } else {
    std::cerr << "[+] LocalAlloc failed for Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  }
}

VOID hdlr_HeapAlloc_before(CHAR *name, size_t bytes) {
  allocated_bytes = bytes;
}

VOID hdlr_HeapAlloc_after(CHAR *name, ADDRINT allocated_addr) {
  // TODO: Parse DECLSPEC_ALLOCATOR HGLOBAL
  if (allocated_addr) {
    PIN_MutexLock(&heap_mutex);
    heap_allocations[allocated_addr] = allocated_bytes;
    PIN_MutexUnlock(&heap_mutex);

    std::cout << "[+] HeapAlloc called: Address="
              << (VOID *)allocated_addr
              << ", Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  } else {
    std::cerr << "[+] HeapAlloc failed for Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  }
}

VOID hdlr_malloc_before(CHAR *name, size_t bytes) {
    allocated_bytes = bytes;
}

VOID hdlr_malloc_after(CHAR *name, ADDRINT allocated_addr) {
    if (allocated_addr) {
        PIN_MutexLock(&heap_mutex);
        heap_allocations[allocated_addr] = allocated_bytes;
        PIN_MutexUnlock(&heap_mutex);

        std::cout << "[+] malloc called: Address="
                  << (VOID *)allocated_addr
                  << ", Size="
                  << std::dec
                  << allocated_bytes << " bytes"
                  << std::endl;
    }
    else {
        std::cerr << "[+] malloc failed for Size="
                  << std::dec
                  << allocated_bytes
                  << " bytes"
                  << std::endl;
    }
}

VOID hdlr_operator_new_before(CHAR *name, size_t bytes) {
    allocated_bytes = bytes;
}

VOID hdlr_operator_new_after(CHAR *name, ADDRINT allocated_addr) {
    if (allocated_addr) {
        PIN_MutexLock(&heap_mutex);
        heap_allocations[allocated_addr] = allocated_bytes;
        PIN_MutexUnlock(&heap_mutex);

        std::cout << "[+] operator new called: Address="
                  << (VOID *)allocated_addr
                  << ", Size="
                  << std::dec
                  << allocated_bytes << " bytes"
                  << std::endl;
    }
    else {
        std::cerr << "[+] operator new failed for Size="
                  << std::dec
                  << allocated_bytes
                  << " bytes"
                  << std::endl;
    }
}

VOID hdlr_VirtualAlloc_before(CHAR *name, size_t bytes) {
  allocated_bytes = bytes;
}

VOID hdlr_VirtualAlloc_after(CHAR *name, ADDRINT allocated_addr) {
  if (allocated_addr) {
    PIN_MutexLock(&heap_mutex);
    heap_allocations[allocated_addr] = allocated_bytes;
    PIN_MutexUnlock(&heap_mutex);

    std::cout << "[+] VirtualAlloc called: Address="
              << (VOID *)allocated_addr
              << ", Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  } else {
    std::cerr << "[+] VirtualAlloc failed for Size="
              << std::dec
              << allocated_bytes << " bytes"
              << std::endl;
  }
}
