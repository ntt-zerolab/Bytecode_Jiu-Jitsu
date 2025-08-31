#include "util.h"


std::string read_file(std::string file_name) {
    std::ifstream f(file_name.c_str());
    if (f.bad()) {
        return "";
    }

    std::ostringstream sstr;
    sstr << f.rdbuf();

    return sstr.str();
}