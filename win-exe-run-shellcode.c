// Copyright (c) 2009-2014, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
// and Peter Ferrie <peter.ferrie@gmail.com>
// Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
// All rights reserved. See COPYRIGHT.txt for details.

// Minimal code for an EXE that executes a shellcode when run.
extern void shellcode(void);

int main(int iArgCount, char** asArgs) {
  shellcode();
  return 0;
}
