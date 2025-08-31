#include "util.h"

extern std::ostream *out;

LPVOID get_err_msg() {
    DWORD err_code;
    LPVOID err_msg;

    err_code = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER
        | FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err_code,
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        (LPTSTR)&err_msg,
        0,
        NULL);

    return err_msg;
}

void print_err_msg() {
    LPVOID err_msg;
    
    err_msg = get_err_msg();
    std::cout << "Error: " << (LPCTSTR)err_msg;
    LocalFree(err_msg);
}

void log_err_msg() {
    LPVOID err_msg;
    
    err_msg = get_err_msg();
    LocalFree(err_msg);
}

std::string read_file(std::string file_name) {
    std::ifstream f(file_name);
    if (!f) {
        std::exit(1);
    }
    auto ss = std::ostringstream{};
    ss << f.rdbuf();
    return ss.str();
}