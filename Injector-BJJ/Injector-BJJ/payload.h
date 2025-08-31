#ifndef _INJECTOR_PAYLOAD_H_
#define _INJECTOR_PAYLOAD_H_

#include <nlohmann/json.hpp>
#include <Windows.h>
#include <string>
#include <vector>

using json = nlohmann::json;

const uint8_t kSymbolTableTypeArray = 0x0;
const uint8_t kSymbolTableTypeLinkedList = 0x1;
const uint8_t kSymbolTableTypeDirect = 0x2;
const uint8_t kSymbolTableScopeGlobal = 0x0;


typedef struct _Bytecode {
    BYTE* bytes;
    SIZE_T len;
} Bytecode;

typedef struct _ValueObject {
    BYTE* bytes;
    SIZE_T len;
    UINT64 index;
} ValueObject;

typedef struct _SymbolTable {
    UINT8 scope;
    std::vector<ValueObject> value_objects;
} SymbolTable;

typedef struct _Payload {
    Bytecode bytecode;
    std::vector<SymbolTable> symbol_tables;
} Payload;


void deserialize_payload(std::string payload_json_string, Payload& payload);


#endif // _INJECTOR_PAYLOAD_H_