#ifndef _EXTRACTOR_BJJ_EXTRACT_H_
#define _EXTRACTOR_BJJ_EXTRACT_H_

#include "common.h"
#include "config.h"
#include "memory.h"
#include "payload.h"

ADDRINT extract_management_structure_addr(CONTEXT *ctxt, ADDRINT *stack_ptr, size_t arg_index);
ADDRINT find_bytecode_addr(ADDRINT management_structure_addr, BytecodeConfig config);
ADDRINT find_symbol_table_addr(ADDRINT management_structure_addr, SymbolTableConfig config);
Bytecode extract_bytecode(ADDRINT management_structure_addr, BytecodeConfig config);
SymbolTable extract_symbol_table(ADDRINT management_structure_addr, SymbolTableConfig config);

#endif  // _EXTRACTOR_BJJ_EXTRACT_H_