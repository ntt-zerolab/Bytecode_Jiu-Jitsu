#include "inject.h"

extern std::ostream *out;

void inject(HANDLE hProcess,
            LPVOID management_structure_addr,
            Payload payload,
            Config config) {

    spdlog::info("Injecting bytecode ... ");

    inject_bytecode(hProcess, management_structure_addr, payload.bytecode, config);

    spdlog::info("Done.");

    inject_symbol_tables(hProcess, management_structure_addr, payload.symbol_tables, config);
}

LPVOID dereference_forward(HANDLE hProcess, LPVOID base_addr, vector<off_t> reference_offsets) {
    LPVOID addr;
    BYTE read_bytes[sizeof(LPVOID)];

    addr = base_addr;
    for (auto iter = reference_offsets.begin(); iter != reference_offsets.end(); iter++) {
        read(hProcess, (LPVOID)((int64_t)addr + *iter), read_bytes, sizeof(read_bytes));
        memcpy(&addr, read_bytes, sizeof(read_bytes));
    }

    return addr;
}

LPVOID find_bytecode_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config) {
    return dereference_forward(hProcess, management_structure_addr, config.bytecode.reference_offsets);
}

LPVOID find_symbol_table_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config) {
    return dereference_forward(hProcess, management_structure_addr, config.symbol_tables[0].reference_offsets);
}

LPVOID find_vpc_addr(HANDLE hProcess, LPVOID management_structure_addr, Config config) {
    LPVOID vpc_addr;
    off_t vpc_offset;

    vpc_offset = config.vpc.reference_offsets.back();
    config.vpc.reference_offsets.pop_back();
    vpc_addr = dereference_forward(hProcess, management_structure_addr, config.vpc.reference_offsets);
    vpc_addr = (LPVOID)((int64_t)vpc_addr + vpc_offset);

    return vpc_addr;
}

void inject_bytecode(HANDLE hProcess, LPVOID management_structure_addr, Bytecode bytecode, Config config) {
    LPVOID bytecode_addr;
    bytecode_addr = find_bytecode_addr(hProcess, management_structure_addr, config);
    spdlog::info("Bytecode cache found at 0x{:x}", (int64_t)bytecode_addr);
    write(hProcess, bytecode_addr, bytecode.bytes, bytecode.len);
}

void inject_symbol_tables(HANDLE hProcess, LPVOID management_structure_addr, vector<SymbolTable> symbol_tables, Config config) {
    LPVOID symbol_table_addr;
    SymbolTable symbol_table;

    for (auto iter = symbol_tables.begin(); iter != symbol_tables.end(); iter++) {
        symbol_table = *iter;
        symbol_table_addr = find_symbol_table_addr(hProcess, management_structure_addr, config);
        spdlog::info("Symbol table found at 0x{:x}", (int64_t)symbol_table_addr);
        inject_symbol_table(hProcess, symbol_table_addr, symbol_table);
    }
}

void inject_symbol_table(HANDLE hProcess, LPVOID symbol_table_addr, SymbolTable symbol_table) {
    LPVOID value_object_addr;
    ValueObject value_object;

    // TODO: add a check regarding the number of value objects where symbol_table.type = kSymbolTableTypeDirect

    for (int i = 0; i < symbol_table.value_objects.size(); i++) {
        value_object_addr = symbol_table_addr;

        value_object = symbol_table.value_objects.at(i);
        spdlog::info("Injecting a symbol table ... ");
        write(hProcess, value_object_addr, value_object.bytes, value_object.len);
        spdlog::info("Done.");
    }
}

void overwrite_vpc(HANDLE hProcess, LPVOID management_structure_addr, Config config, LPVOID bytecode_addr) {
    LPVOID vpc_addr = find_vpc_addr(hProcess, management_structure_addr, config);
    spdlog::info("VPC found at 0x{:x}", (int64_t)vpc_addr);
    spdlog::info("Overwriting VPC to 0x{:x} ...", (int64_t)bytecode_addr);
    write(hProcess, vpc_addr, (BYTE *)&bytecode_addr, sizeof(LPVOID));
    spdlog::info("Done.");
}

void read(HANDLE hProcess, LPVOID addr, BYTE *bytes, SIZE_T bytes_len) {
    /*
    BOOL ReadProcessMemory(
    [in]  HANDLE  hProcess,
    [in]  LPCVOID lpBaseAddress,
    [out] LPVOID  lpBuffer,
    [in]  SIZE_T  nSize,
    [out] SIZE_T  *lpNumberOfBytesRead
    );
    */
    SIZE_T read_len;
    BOOL result;
    result = ReadProcessMemory(hProcess,
            addr,
            bytes,
            bytes_len,
            &read_len);

    if (result == 0)
        log_err_msg();

    if (read_len != bytes_len)
        *out << "Error: could not read all bytes. "
             << read_len
             << " bytes read."
             << std::endl;
}

void write(HANDLE hProcess, LPVOID addr, BYTE *bytes, SIZE_T bytes_len) {
    /*
    BOOL WriteProcessMemory(
    [in]  HANDLE  hProcess,
    [in]  LPVOID  lpBaseAddress,
    [in]  LPCVOID lpBuffer,
    [in]  SIZE_T  nSize,
    [out] SIZE_T  *lpNumberOfBytesWritten
    );
    */
    SIZE_T write_len;
    BOOL result;
    result = WriteProcessMemory(hProcess,
            addr,
            bytes,
            bytes_len,
            &write_len);

    if (result == 0)
        log_err_msg();

    if (write_len != bytes_len)
        *out << "Error: could not write all bytes. "
             << write_len
             << " bytes written."
             << std::endl;
}
