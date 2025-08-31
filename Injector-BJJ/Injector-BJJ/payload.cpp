#include "payload.h"


void deserialize_payload(std::string payload_json_string, Payload& payload) {
    std::string bytecode_bytes;
    std::string symbol_table_bytes;
    auto payload_json = json::parse(payload_json_string);

    try {
        auto bytecode = payload_json.at("bytecode");
        payload.bytecode.len = bytecode.at("len").get<int>();
        for (auto i = 0; i < payload.bytecode.len; i++) {
            bytecode_bytes += bytecode.at("bytes")[i].get<BYTE>();
        }
        payload.bytecode.bytes = new BYTE[payload.bytecode.len + 1];
        memcpy(payload.bytecode.bytes, (BYTE*)bytecode_bytes.data(), payload.bytecode.len);

        auto symbol_tables = payload_json.at("symbol_tables");
        for (auto symbol_table_it = symbol_tables.begin(); symbol_table_it != symbol_tables.end(); symbol_table_it++) {
            SymbolTable symbol_table;
            symbol_table.scope = symbol_table_it->at("scope").get<UINT8>();
            auto value_objects = symbol_table_it->at("value_objects");
            for (auto value_object_it = value_objects.begin(); value_object_it != value_objects.end(); value_object_it++) {
                ValueObject value_object;
                std::string value_object_bytes;
                value_object.len = value_object_it->at("len").get<SIZE_T>();
                for (auto i = 0; i < value_object.len; i++) {
                    value_object_bytes += value_object_it->at("bytes")[i].get<BYTE>();
                }
                value_object.bytes = new BYTE[value_object.len + 1];
                memcpy(value_object.bytes, (BYTE*)value_object_bytes.data(), value_object.len);
                value_object.index = value_object_it->at("index").get<UINT64>();
                symbol_table.value_objects.push_back(value_object);
            }
            payload.symbol_tables.push_back(symbol_table);
        }
    }
    catch (const std::exception& err) {
        std::exit(1);
    }
}