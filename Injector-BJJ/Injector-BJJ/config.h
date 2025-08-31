#ifndef _INJECTOR_CONFIG_H_
#define _INJECTOR_CONFIG_H_

#include "common.h"
#include <nlohmann/json.hpp>
#include <Windows.h>
#include <string>
#include <vector>

using json = nlohmann::json;
using std::vector;


typedef struct _BytecodeConfig {
    std::vector<off_t> reference_offsets;
} BytecodeConfig;

typedef struct _SymbolTableConfig {
    UINT8 type;
    UINT8 scope;
    std::vector<off_t> reference_offsets;
    off_t forward_link_offset;
} SymbolTableConfig;

typedef struct _VPCConfig {
    std::vector<off_t> reference_offsets;
} VPCConfig;

typedef struct _Config {
    std::string interp_module_name;
    off_t interp_func_offset;
    int management_structure_index;
    BytecodeConfig bytecode;
    std::vector<SymbolTableConfig> symbol_tables;
    VPCConfig vpc;
} Config;


void deserialize_config(std::string config_json_string, Config& config);

#endif  // _INJECTOR_CONFIG_H_