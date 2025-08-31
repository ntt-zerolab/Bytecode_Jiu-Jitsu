#ifndef _INJECTOR_VPC_H_
#define _INJECTOR_VPC_H_

#include <Windows.h>
#include <vector>

using std::vector;

typedef struct _VPC {
    vector<off_t> reference_offsets;
} VPC;

#endif // _INJECTOR_VPC_H_