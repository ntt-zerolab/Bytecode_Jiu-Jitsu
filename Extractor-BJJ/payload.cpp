#include "payload.h"


std::string serialize_payload(Payload payload) {
    json payload_json;

    for (auto i = 0; i < payload.bytecode.len; i++) {
        payload_json["bytecode"]["bytes"][i] = payload.bytecode.bytes[i];
    }
    payload_json["bytecode"]["len"] = payload.bytecode.len;

    for (auto i = 0; i < payload.symbol_tables.size(); i++) {
        payload_json["symbol_tables"][i]["scope"] = payload.symbol_tables[i].scope;
        for (auto j = 0; j < payload.symbol_tables[i].value_objects.size(); j++) {
            for (auto k = 0; k < payload.symbol_tables[i].value_objects[j].len; k++) {
                payload_json["symbol_tables"][i]["value_objects"][j]["bytes"][k] = payload.symbol_tables[i].value_objects[j].bytes[k];
            }
            payload_json["symbol_tables"][i]["value_objects"][j]["len"] = payload.symbol_tables[i].value_objects[j].len;
            payload_json["symbol_tables"][i]["value_objects"][j]["index"] = payload.symbol_tables[i].value_objects[j].index;
        }
    }

    return payload_json.dump(4);
}