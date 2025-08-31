#ifndef _EXTRACTOR_BJJ_PAYLOAD_H_
#define _EXTRACTOR_BJJ_PAYLOAD_H_

#include "common.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const UINT8 kSymbolTableTypeArray = 0x0;
const UINT8 kSymbolTableTypeLinkedList = 0x1;
const UINT8 kSymbolTableTypeDirect = 0x2;
const UINT8 kSymbolTableScopeGlobal = 0x0;
constexpr UINT8 kPayloadFileTypeJson = 0;
constexpr UINT8 kPayloadFileTypeCHeader = 1;

typedef struct _Bytecode {
    std::vector<UINT8> bytes;
    size_t len;
} Bytecode;

typedef struct _ValueObject {
    std::vector<UINT8> bytes;
    size_t len;
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

string serialize_payload(Payload payload);

#endif  // _EXTRACTOR_BJJ_PAYLOAD_H_