#ifndef _INJECTOR_STACK_H_
#define _INJECTOR_STACK_H_

typedef struct _StackInfo {
    LPVOID base;
    LPVOID limit;
    SIZE_T size;
} StackInfo;

#endif // _INJECTOR_STACK_H_