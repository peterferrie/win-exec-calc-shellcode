win-exec-calc-shellcode
-----------------------
Small null-free shellcode that execute calc.exe.
Runs on x86 and x64 versions of Windows 5.0-6.3 (2000, XP, 2003, 2008, 7, 8, 8.1), all service packs.

Sizes (build 306)
-----------------
<table class="wikitable">
  <tr>
    <td style="border: 1px solid #ccc; padding: 5px;"> platform </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> size </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> stack align </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> function wrapper </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> func+save regs </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> func+stack </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> func+stack+regs </td>
  </tr><tr>
    <td style="border: 1px solid #ccc; padding: 5px;"> x86 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 72 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 75 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 77 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 77 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 84 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 84 </td>
  </tr><tr>
    <td style="border: 1px solid #ccc; padding: 5px;"> x64 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 85 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 90 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 98 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 105 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 106 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 112 </td>
  </tr><tr>
    <td style="border: 1px solid #ccc; padding: 5px;"> x86+x64 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 113 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 118 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 179 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 188 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 188 </td>
    <td style="border: 1px solid #ccc; padding: 5px;"> 196 </td>
  </tr>
</table>
  
Features
--------
* NUL Free 
* Windows version and service pack independent. 
* <a href="http://en.wikipedia.org/wiki/Instruction_set">ISA</a> independent:
  runs on x86 (w32-exec-calc-shellcode) or x64 (w64-exec-calc-shellcode)
  architecture, or both (win-exec-calc-shellcode). 
* Stack pointer can be aligned if needed (if you are seeing crashes in
  WinExec, try using the stack aligning version). 
* No assumptions are made about the values in registers or on the stack. 
* x86: <a href="http://en.wikipedia.org/wiki/3_GB_barrier">/3GB</a> and
  <a href="http://en.wikipedia.org/wiki/WoW64">WoW64</a>" compatible (pointers
  are not assumed to be smaller than 0x80000000). 
* <a href="http://en.wikipedia.org/wiki/Data_Execution_Prevention">DEP</a> /
  <a href="http://en.wikipedia.org/wiki/Address_space_layout_randomization">ASLR</a>
  compatible: data is not executed, code is not modified. 
* Able to save and restore registers and return, for use in PoC code that calls
  the shellcode as a function (using <a href="http://en.wikipedia.org/wiki/X86_calling_conventions">
  cdecl/stdcall/fastcall</a> calling convention.

Credits
-------
<a href="http://skylined.nl/">Skylined</a> and <a href="http://pferrie.host22.com/">Peter Ferrie</a>
