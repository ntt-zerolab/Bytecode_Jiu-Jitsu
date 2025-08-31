#ifndef _TRACER_BJJ_CONFIG_H_
#define _TRACER_BJJ_CONFIG_H_

#include "common.h"


typedef struct _Config {
    std::string target_module_name;
    off_t interp_func_offset;
    off_t decoder_offset;
} Config;

std::pair<std::string, std::string> get_config_item(std::string config_line);
Config *parse_config(std::string config_string);
BOOL is_config_valid(Config config);

#endif  // _TRACER_BJJ_CONFIG_H_