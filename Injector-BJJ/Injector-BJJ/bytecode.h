#ifndef _INJECTOR_BYTECODE_H_
#define _INJECTOR_BYTECODE_H_

#include <Windows.h>
#include <vector>

using std::vector;

typedef struct _Bytecode {
    BYTE *bytes;
    int len;
    vector<off_t> reference_offsets;
} Bytecode;

#endif // _INJECTOR_BYTECODE_H_