#ifndef _INJECTOR_UTIL_H_
#define _INJECTOR_UTIL_H_

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>

LPVOID get_err_msg();
void print_err_msg();
void log_err_msg();
std::string read_file(std::string file_name);

#endif // _INJECTOR_UTIL_H_