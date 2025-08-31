#ifndef _INJECTOR_INJECT_H_
#define _INJECTOR_INJECT_H_

#include "config.h"
#include "common.h"
#include "payload.h"
#include "util.h"
#include "vpc.h"
#include <Windows.h>
#include <iomanip>
#include <iostream>
#include <list>

using std::vector;

void inject(HANDLE hProcess, LPVOID management_structure_addr, Payload payload, Config config);
LPVOID find_bytecode_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config);
LPVOID find_symbol_table_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config);
LPVOID find_vpc_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config);
void inject_bytecode(HANDLE hProcess, LPVOID management_structure_addr, Bytecode bytecode, Config config);
void inject_symbol_tables(HANDLE hProcess, LPVOID management_structure_addr, vector<SymbolTable> symbol_tables, Config config);
void inject_symbol_table(HANDLE hProcess, LPVOID symbol_table_addr, SymbolTable symbol_table);
void overwrite_vpc(HANDLE hProcess, LPVOID management_structure_addr, Config config, LPVOID bytecode_addr);
void read(HANDLE hProcess, LPVOID addr, BYTE *bytes, SIZE_T bytes_len);
void write(HANDLE hProcess, LPVOID addr, BYTE *bytes, SIZE_T bytes_len);
 
#endif  // _INJECTOR_INJECT_H_