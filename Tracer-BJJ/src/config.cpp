#include "config.h"
#include <string>


std::pair<std::string, std::string> get_config_item(std::string config_line) {
    std::stringstream ss(config_line);
    std::string elem;
    std::string val;
    std::pair <std::string, std::string> config_item;

    getline(ss, elem, '=');
    getline(ss, val, '=');

    config_item = std::make_pair(elem, val);

    return config_item;
}

Config *parse_config(std::string config_string) {
    Config *config;
    std::stringstream ss(config_string);
    std::string config_line;
    std::pair <std::string, std::string> config_item;

    config = new Config;

    while(getline(ss, config_line)) {
        config_item = get_config_item(config_line);
        if (config_item.first == "target_module_name") {
            config->target_module_name = config_item.second;
        }
        else if (config_item.first == "interp_func_offset") {
            config->interp_func_offset = strtol(config_item.second.c_str(), nullptr, 16);
        }
        else if (config_item.first == "decoder_offset") {
            config->decoder_offset = strtol(config_item.second.c_str(), nullptr, 16);
        }
    }

    return config;
}

BOOL is_config_valid(Config config) {
    if (config.target_module_name.size() == 0
            || config.interp_func_offset == 0
            || config.decoder_offset == 0)
        return false;
    return true;
}