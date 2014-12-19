Small null-free shellcode that execute calc.exe. Runs on x86 and x64 versions of Windows 5.0-6.3 (2000, XP, 2003, 2008, 7, 8, 8.1), all service packs. 

Sizes (build 306) 

platform	size		stack align		function wrapper		func+save regs	func+stack		func+stack+regs  
x86		72		75			77				77			84			84  
x64		85		90			98				105			106			112  
x86+x64	113		118			179				188			188			196  


Features: 
•NULL Free 
•Windows version and service pack independent. 
•ISA independent: runs on x86 (w32-exec-calc-shellcode) or x64 (w64-exec-calc-shellcode) architecture, or both x86 and x64 architecture (win-exec-calc-shellcode). 
•Stack pointer can be aligned if needed (if you are seeing crashes in WinExec, try using the stack aligning version). 
•No assumptions are made about the values in registers or on the stack. 
•x86: "/3GB" and WoW64 compatible: pointers are not assumed to be smaller than 0x80000000. 
•DEP/ASLR compatible: data is not executed, code is not modified. 
•Able to save and restore registers and return for use in PoC code that calls the shellcode as a function using cdecl/stdcall/fastcall calling convention. 
