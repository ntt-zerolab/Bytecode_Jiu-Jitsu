#include "print.h"

void print_config_string(std::string config_string) {
    std::cout << "[+] Config string: " << std::endl << config_string << std::endl;
}

void print_config(Config config) {
    std::cout << "[+] Target module name: " << config.target_module_name << std::endl;
    std::cout << "[+] Interp function offset: " << (void *)config.interp_func_offset << std::endl;
    std::cout << "[+] Decoder offset: " << (void *)config.decoder_offset << std::endl;
}