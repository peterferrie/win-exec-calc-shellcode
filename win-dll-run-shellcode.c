// Copyright (c) 2009-2014, Berend-Jan "SkyLined" Wever <win-exec-calc-shellcode@skylined.nl>
// and Peter Ferrie <peter.ferrie@gmail.com>
// Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
// All rights reserved. See COPYRIGHT.txt for details.

// Minimal code for a DLL that executes a shellcode when loaded into a process.
#include <windows.h>
extern void shellcode(void);

#pragma warning( push ) 
#pragma warning( disable : 4100 )
__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hInstance,DWORD fwdReason, LPVOID lpvReserved) {
  shellcode();
  return FALSE;
}
#pragma warning( pop )
