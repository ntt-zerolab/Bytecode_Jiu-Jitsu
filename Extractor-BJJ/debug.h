#ifndef _EXTRACTOR_BJJ_DEBUG_H_
#define _EXTRACTOR_BJJ_DEBUG_H_

#include "common.h"
namespace WINDOWS
{
#define _WINDOWS_H_PATH_ C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
// #define _WINDOWS_H_PATH_ ..\..\..\extras\crt\include
#include <Windows.h>
}

VOID wait_for_debugger_attach(UINT32 sleep_seconds);

#endif  // _EXTRACTOR_BJJ_DEBUG_H_