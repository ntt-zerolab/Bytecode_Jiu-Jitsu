#include "config.h"


void deserialize_config(std::string config_json_string, Config& config) {
    auto config_json = json::parse(config_json_string);

    try {
        config.interp_module_name = config_json.at("interp_module_name").get<std::string>();
        config.interp_func_offset = config_json.at("interp_func_offset").get<off_t>();
        config.management_structure_index = config_json.at("management_structure_index").get<int>();
        config_json.at("bytecode").at("reference_offsets").get_to(config.bytecode.reference_offsets);
        config_json.at("vpc").at("reference_offsets").get_to(config.vpc.reference_offsets);
        auto symbol_tables = config_json.at("symbol_tables");
        for (auto it = symbol_tables.begin(); it != symbol_tables.end(); it++) {
            SymbolTableConfig symbol_table_config;
            symbol_table_config.type = it->at("type");
            symbol_table_config.scope = it->at("scope");
            it->at("reference_offsets").get_to(symbol_table_config.reference_offsets);
            symbol_table_config.forward_link_offset = it->at("forward_link_offset");
            config.symbol_tables.push_back(symbol_table_config);
        }
    }
    catch (const std::exception& err) {
        spdlog::error(err.what());
        std::exit(1);
    }
}