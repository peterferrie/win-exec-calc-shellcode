; Copyright (c) 2009-2014, Berend-Jan "SkyLined" Wever <win-exec-calc-shellcode@skylined.nl>
; and Peter Ferrie <peter.ferrie@gmail.com>
; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.

; Macros for converting between bytes, words, dwords and qwords
%define B2W(b1,b2)                      (((b2) << 8) + (b1))
%define W2DW(w1,w2)                     (((w2) << 16) + (w1))
%define DW2QW(dw1,dw2)                  (((dw2) << 32) + (dw1))
%define B2DW(b1,b2,b3,b4)               ((B2W(b3, b4) << 16) + B2W(b1, b2))
%define B2QW(b1,b2,b3,b4,b5,b6,b7,b8)   ((B2DW(b5,b6,b7,b8) << 32) + B2DW(b1,b2,b3,b4))
%define W2QW(w1,w2,w3,w4)               ((W2DW(w3,w4) << 32) + W2DW(w1,w2))

