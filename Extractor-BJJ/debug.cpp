#include "debug.h"

VOID wait_for_debugger_attach(UINT32 sleep_seconds) {
	cout << "[+] Waiting for debugger attach ("
		 << dec
		 << sleep_seconds
		 << " sec sleep) ..." << endl;

	WINDOWS:: Sleep(sleep_seconds * 1000);

	cout << "[+] Sleep finished.";
}