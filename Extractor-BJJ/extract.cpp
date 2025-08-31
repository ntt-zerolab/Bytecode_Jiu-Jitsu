#include "extract.h"

// Function to extract a specific argument as an address
ADDRINT extract_management_structure_addr(CONTEXT *ctxt, ADDRINT *stack_ptr, size_t arg_index) {
  bool is_64bit = (sizeof(ADDRINT) == 8);
  arg_index--;

  if (is_64bit) {
    if (arg_index < 4) {
      switch (arg_index) {
        case 0:
          return PIN_GetContextReg(ctxt, REG_RCX);
        case 1:
          return PIN_GetContextReg(ctxt, REG_RDX);
        case 2:
          return PIN_GetContextReg(ctxt, REG_R8);
        case 3:
          return PIN_GetContextReg(ctxt, REG_R9);
        default:
          break;
      }
    } else {
      return *(stack_ptr + (arg_index - 4));
    }
  } else {
    return *(stack_ptr + arg_index);
  }
}

// Function to traverse a structure using offsets
ADDRINT dereference_forward(ADDRINT base_addr, const vector<off_t>& reference_offsets) {
  ADDRINT current_addr;

  current_addr = base_addr;
  for (auto offset : reference_offsets) {
    cout << "[+] Current address: "
         << (VOID*)current_addr
         << endl;
    cout << "[+] Offset: "
         << showbase
         << hex
         << offset
         << endl;

    if (current_addr == 0) {
      cerr << "Null pointer encountered during structure traversal." << endl;
      return 0;
    }

    cout << "[+] Next address: "
         << (VOID *)(current_addr + offset)
         << endl;
    current_addr = *reinterpret_cast<ADDRINT *>(current_addr + offset);
  }

  return current_addr;
}

ADDRINT find_bytecode_addr(ADDRINT management_structure_addr, BytecodeConfig config) {
  return dereference_forward(management_structure_addr, config.reference_offsets);
}

ADDRINT find_symbol_table_addr(ADDRINT management_structure_addr, SymbolTableConfig config) {
  return dereference_forward(management_structure_addr, config.reference_offsets);
}

Bytecode extract_bytecode(ADDRINT management_structure_addr, BytecodeConfig config) {
    Bytecode bytecode;
    ADDRINT bytecode_addr;

    cout << "[+] Finding bytecode cache ..." << endl;

    bytecode_addr = find_bytecode_addr(management_structure_addr, config);
    bytecode.len = lookup_heap_size(bytecode_addr);

    cout << "[+] Found bytecode address: "
        << (VOID*)bytecode_addr
        << endl;
    cout << "[+] Found bytecode size: "
        << dec
        << bytecode.len
        << endl;

    if (bytecode.len == 0) {
        bytecode.len = 0x100;
        cout << "[+] Bytecode size is set to 0x100." << endl;
    }

    bytecode.bytes.resize(bytecode.len);
    PIN_SafeCopy(bytecode.bytes.data(), reinterpret_cast<void*>(bytecode_addr), bytecode.len);

    bytecode.len = bytecode.bytes.size();
    cout << "[+] Extracted bytecode size: "
        << dec
        << bytecode.len
        << endl;
    cout << "[+] Extracted bytecode bytes: ";
    for (auto i = 0; i < bytecode.len; i++) {
        cout << "\\x"
            << hex
            << setw(2)
            << setfill('0')
            << noshowbase
            << (int)bytecode.bytes[i];
    }
    cout << endl;

    return bytecode;
}

ValueObject extract_value_object(ADDRINT value_object_addr) {
  ValueObject value_object;

  value_object.len = lookup_heap_size(value_object_addr);

  cout << "[+] Found value object address: "
       << (VOID*)value_object_addr
       << endl;
  cout << "[+] Found symbol table size: "
       << dec
       << value_object.len
       << endl;

  if (value_object.len == 0) {
      value_object.len = 0x100;
      cout << "[+] Symbol table size is set to 0x100." << endl;
  }

  value_object.bytes.resize(value_object.len);
  PIN_SafeCopy(value_object.bytes.data(), reinterpret_cast<void*>(value_object_addr), value_object.len);

  value_object.len = value_object.bytes.size();
  cout << "[+] Extracted value object size: "
       << dec
       << value_object.len
       << endl;
  cout << "[+] Extracted value object bytes: ";
  for (auto i = 0; i < value_object.len; i++) {
      cout << "\\x"
           << hex
           << setw(2)
           << setfill('0')
           << noshowbase
           << (int)value_object.bytes[i];
  }
  cout << endl;

  return value_object;
}

SymbolTable extract_symbol_table(ADDRINT management_structure_addr, SymbolTableConfig config) {
  SymbolTable symbol_table;
  ADDRINT symbol_table_addr;

  cout << "[+] Finding symbol table ..." << endl;

  symbol_table_addr = find_symbol_table_addr(management_structure_addr, config);
  symbol_table.scope = kSymbolTableScopeGlobal;

  cout << "[+] Found symbol table address: "
       << (VOID*)symbol_table_addr
       << endl;

  symbol_table.value_objects.push_back(extract_value_object(symbol_table_addr));

  return symbol_table;
}
