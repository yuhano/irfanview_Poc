## irfanview PoC Vulnerability Analysis
## Overview
* A free image viewer available for Windows.
* The Korean translation is available at the following link.
    * https://github.com/yuhano/irfanview_Poc/blob/main/README_KR.md

## Vulnerability 1
## Product Information
* Plugin: Exr.dll - 4.67.1.0

## File Information
### Extension.
* exr

### File name
* 0001.exr

## Vulnerability description
* When executing certain files in irfanview version 4.67, an access violation occurs in EXR!ReadEXR+0x40ef1.

### Vulnerability POC
```
(b390.a254): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
00007ffb`24febed4 cc              int     3
0:000> g
ModLoad: 00007ffb`24870000 00007ffb`248a1000   C:\WINDOWS\System32\IMM32.DLL
ModLoad: 00007ffb`1e880000 00007ffb`1e930000   C:\WINDOWS\system32\uxtheme.dll
ModLoad: 00007ffb`23140000 00007ffb`234cd000   C:\WINDOWS\System32\combase.dll
ModLoad: 00007ffb`24cf0000 00007ffb`24e4b000   C:\WINDOWS\System32\MSCTF.dll
ModLoad: 00007ffb`033c0000 00007ffb`03470000   C:\WINDOWS\SYSTEM32\TextShaping.dll
ModLoad: 00007ffb`24810000 00007ffb`2486e000   C:\WINDOWS\System32\SHLWAPI.dll
ModLoad: 00007ffa`e3cf0000 00007ffa`e3d8c000   C:\WINDOWS\system32\IMGSF50Filter_x64.dll
ModLoad: 00007ffb`24270000 00007ffb`24415000   C:\WINDOWS\System32\ole32.dll
ModLoad: 00007ffb`248b0000 00007ffb`248b8000   C:\WINDOWS\System32\PSAPI.DLL
ModLoad: 00007ffb`05210000 00007ffb`05310000   C:\WINDOWS\SYSTEM32\Opengl32.dll
ModLoad: 00007ffb`04d20000 00007ffb`04d4d000   C:\WINDOWS\SYSTEM32\GLU32.dll
ModLoad: 00007ffb`1ea20000 00007ffb`1ea57000   C:\WINDOWS\SYSTEM32\dxcore.dll
ModLoad: 00007ffb`21220000 00007ffb`21238000   C:\WINDOWS\SYSTEM32\kernel.appcore.dll
ModLoad: 00007ffb`22610000 00007ffb`2268b000   C:\WINDOWS\System32\bcryptPrimitives.dll
ModLoad: 00007ffb`24910000 00007ffb`249e7000   C:\WINDOWS\System32\OLEAUT32.dll
ModLoad: 00007ffb`027b0000 00007ffb`028fe000   C:\WINDOWS\SYSTEM32\textinputframework.dll
ModLoad: 00007ffb`051a0000 00007ffb`05209000   C:\WINDOWS\system32\Oleacc.dll
ModLoad: 00007ff9`def00000 00007ff9`df25f000   C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
(b390.a254): C++ EH exception - code e06d7363 (first chance)
(b390.a254): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
EXR!ReadEXR+0x40ef1:
00007ff9`def42de1 66418901        mov     word ptr [r9],ax ds:000001ea`00d1f6f6=????

0:000> t
(b390.a254): Access violation - code c0000005 (!!! second chance !!!)
EXR!ReadEXR+0x40ef1:
00007ff9`def42de1 66418901        mov     word ptr [r9],ax ds:000001ea`00d1f6f6=????

0:000> r
rax=0000000000003c00 rbx=0000000000000008 rcx=00000000cccccccc
rdx=0000000000003c00 rsi=0000000000000001 rdi=0000000000000001
rip=00007ff9def42de1 rsp=00000020ddefd050 rbp=00000020ddefd150
 r8=00000000cccccccc  r9=000001ea00d1f6f6 r10=00000000ccccccea
r11=0000000007800000 r12=0000000000000001 r13=00000000ffffffff
r14=0000000033333334 r15=00000000cccccccc
iopl=0         nv up ei ng nz na po cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010285
EXR!ReadEXR+0x40ef1:
00007ff9`def42de1 66418901        mov     word ptr [r9],ax ds:000001ea`00d1f6f6=????

0:000> kv
 # Child-SP          RetAddr               : Args to Child                                                           : Call Site
00 00000020`ddefd050 00007ff9`def4388a     : 00000000`00000010 0000021a`00d1f820 0000021a`00cf6070 0000021a`00cf6070 : EXR!ReadEXR+0x40ef1
01 00000020`ddefd200 00007ff9`def0dd7e     : 0000021a`00cf6070 00000000`00000000 00000020`ddefd540 0000021a`00d1f6f0 : EXR!ReadEXR+0x4199a
02 00000020`ddefd240 00007ff9`def02572     : 00000000`0000001f 00000000`0000001f 00000000`00000060 00000000`0000001f : EXR!ReadEXR+0xbe8e
03 00000020`ddefd2e0 00007ff7`1a95dd0c     : 00000000`00000000 00007ff9`def01ef0 00000020`ddefdd60 00000020`ddefdd60 : EXR!ReadEXR+0x682
04 00000020`ddefd440 00007ff7`1a984ed4     : 0000021a`00cea740 00000000`00001030 00000000`0000007f 00000000`00001830 : i_view64+0x8dd0c
05 00000020`ddefdc50 00007ff7`1a983ce8     : 00000000`00000000 00000000`00000000 00000020`ddefeb50 00007ff7`1aaefd40 : i_view64+0xb4ed4
06 00000020`ddefea80 00007ff7`1a956b52     : 00000000`00000384 00000000`00000384 00000000`00000005 00007ff7`1a8d0000 : i_view64+0xb3ce8
07 00000020`ddeff5e0 00007ff7`1a9e64b0     : 00000000`00000000 00000000`00000000 00000000`0000000a 00007ff7`1a8d0000 : i_view64+0x86b52
08 00000020`ddeffbf0 00007ffb`2449257d     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : i_view64+0x1164b0
09 00000020`ddeffc30 00007ffb`24f6af28     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x1d
0a 00000020`ddeffc60 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x28

0:000> u
EXR!ReadEXR+0x40ef1:
00007ff9`def42de1 66418901        mov     word ptr [r9],ax
00007ff9`def42de5 03cf            add     ecx,edi
00007ff9`def42de7 448b542470      mov     r10d,dword ptr [rsp+70h]
00007ff9`def42dec 4c03cb          add     r9,rbx
00007ff9`def42def 413bca          cmp     ecx,r10d
00007ff9`def42df2 7eed            jle     EXR!ReadEXR+0x40ef1 (00007ff9`def42de1)
00007ff9`def42df4 448b442430      mov     r8d,dword ptr [rsp+30h]
00007ff9`def42df9 eb31            jmp     EXR!ReadEXR+0x40f3c (00007ff9`def42e2c)
```

## Vulnerability 2
## Product Information
* Plugin: Exr.dll - 4.67.1.0

## File Information
### Extension.
* exr

### File name
* 0002.exr

## Vulnerability description
* When executing certain files in irfanview version 4.67, an access violation occurs in EXR!ReadEXR+0x4eef0.

### Vulnerability POC
```
(5550.8528): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
00007ffb`24febed4 cc              int     3
0:000> g
ModLoad: 00007ffb`24870000 00007ffb`248a1000   C:\WINDOWS\System32\IMM32.DLL
ModLoad: 00007ffb`1e880000 00007ffb`1e930000   C:\WINDOWS\system32\uxtheme.dll
ModLoad: 00007ffb`23140000 00007ffb`234cd000   C:\WINDOWS\System32\combase.dll
ModLoad: 00007ffb`24cf0000 00007ffb`24e4b000   C:\WINDOWS\System32\MSCTF.dll
ModLoad: 00007ffb`033c0000 00007ffb`03470000   C:\WINDOWS\SYSTEM32\TextShaping.dll
ModLoad: 00007ffb`24810000 00007ffb`2486e000   C:\WINDOWS\System32\SHLWAPI.dll
ModLoad: 00007ffa`e3cf0000 00007ffa`e3d8c000   C:\WINDOWS\system32\IMGSF50Filter_x64.dll
ModLoad: 00007ffb`24270000 00007ffb`24415000   C:\WINDOWS\System32\ole32.dll
ModLoad: 00007ffb`248b0000 00007ffb`248b8000   C:\WINDOWS\System32\PSAPI.DLL
ModLoad: 00007ffb`05210000 00007ffb`05310000   C:\WINDOWS\SYSTEM32\Opengl32.dll
ModLoad: 00007ffb`04d20000 00007ffb`04d4d000   C:\WINDOWS\SYSTEM32\GLU32.dll
ModLoad: 00007ffb`1ea20000 00007ffb`1ea57000   C:\WINDOWS\SYSTEM32\dxcore.dll
ModLoad: 00007ffb`21220000 00007ffb`21238000   C:\WINDOWS\SYSTEM32\kernel.appcore.dll
ModLoad: 00007ffb`22610000 00007ffb`2268b000   C:\WINDOWS\System32\bcryptPrimitives.dll
ModLoad: 00007ffb`24910000 00007ffb`249e7000   C:\WINDOWS\System32\OLEAUT32.dll
ModLoad: 00007ffb`027b0000 00007ffb`028fe000   C:\WINDOWS\SYSTEM32\textinputframework.dll
ModLoad: 00007ffb`051a0000 00007ffb`05209000   C:\WINDOWS\system32\Oleacc.dll
ModLoad: 00007ff9`df110000 00007ff9`df46f000   C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
(5550.8528): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
EXR!ReadEXR+0x4eef0:
00007ff9`df160de0 660fe701        movntdq xmmword ptr [rcx],xmm0 ds:000051ea`12af6480=????????????????????????????????

0:000> t
(5550.8528): Access violation - code c0000005 (!!! second chance !!!)
EXR!ReadEXR+0x4eef0:
00007ff9`df160de0 660fe701        movntdq xmmword ptr [rcx],xmm0 ds:000051ea`12af6480=????????????????????????????????

0:000> r
rax=0000003eebafce98 rbx=0000003eebafcf58 rcx=000051ea12af6480
rdx=0000000000000001 rsi=0000003eebafcf40 rdi=0000003eebafcf48
rip=00007ff9df160de0 rsp=0000003eebafce30 rbp=0000000000000000
 r8=0000003eebafcf50  r9=0000000000000000 r10=0000003eebafce90
r11=0000000000000002 r12=0000021a16aa4040 r13=0000021a12b11ee0
r14=000051ea12af6480 r15=0000021a12b11790
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010200
EXR!ReadEXR+0x4eef0:
00007ff9`df160de0 660fe701        movntdq xmmword ptr [rcx],xmm0 ds:000051ea`12af6480=????????????????????????????????

0:000> kv
 # Child-SP          RetAddr               : Args to Child                                                           : Call Site
00 0000003e`ebafce30 00007ff9`df1603f2     : 00000000`00000001 0000021a`12ae3960 00000000`00000004 00000000`30303030 : EXR!ReadEXR+0x4eef0
01 0000003e`ebafce50 00007ff9`df16764c     : 00000001`12b10c01 0000021a`12b11790 0000021a`12b11790 00007ff9`df1a5e6f : EXR!ReadEXR+0x4e502
02 0000003e`ebafcfc0 00007ff9`df1673a3     : 00000000`00000000 00007ff9`df166af3 ffffffff`fffffffe 0000021a`50000063 : EXR!ReadEXR+0x5575c
03 0000003e`ebafcff0 00007ff9`df161848     : 0000021a`12adc610 0000021a`12adc610 0000021a`12ae9610 00007ff9`df145d92 : EXR!ReadEXR+0x554b3
04 0000003e`ebafd040 00007ff9`df1538aa     : 00000000`00000010 0000021a`12b10cc0 00000000`00000000 ffffffff`fffffffe : EXR!ReadEXR+0x4f958
05 0000003e`ebafd320 00007ff9`df11dd7e     : 00000001`00000001 00000000`00000000 0000003e`ebafd660 0000021a`12af6480 : EXR!ReadEXR+0x419ba
06 0000003e`ebafd360 00007ff9`df112572     : 00000000`00003501 00000000`00003501 00000000`00009f04 00000000`00003501 : EXR!ReadEXR+0xbe8e
07 0000003e`ebafd400 00007ff7`1a95dd0c     : 00000000`00000000 00007ff9`df111ef0 0000003e`ebafde80 0000003e`ebafde80 : EXR!ReadEXR+0x682
08 0000003e`ebafd560 00007ff7`1a984ed4     : 0000021a`12ada740 00000000`00001030 00000000`0000007f 00000000`00001830 : i_view64+0x8dd0c
09 0000003e`ebafdd70 00007ff7`1a983ce8     : 00000000`00000000 00000000`00000000 0000003e`ebafec70 00007ff7`1aaefd40 : i_view64+0xb4ed4
0a 0000003e`ebafeba0 00007ff7`1a956b52     : 00000000`00000384 00000000`00000384 00000000`00000005 00007ff7`1a8d0000 : i_view64+0xb3ce8
0b 0000003e`ebaff700 00007ff7`1a9e64b0     : 00000000`00000000 00000000`00000000 00000000`0000000a 00007ff7`1a8d0000 : i_view64+0x86b52
0c 0000003e`ebaffd10 00007ffb`2449257d     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : i_view64+0x1164b0
0d 0000003e`ebaffd50 00007ffb`24f6af28     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x1d
0e 0000003e`ebaffd80 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x28

0:000> u
EXR!ReadEXR+0x4eef0:
00007ff9`df160de0 660fe701        movntdq xmmword ptr [rcx],xmm0
00007ff9`df160de4 48830010        add     qword ptr [rax],10h
00007ff9`df160de8 660f6fc6        movdqa  xmm0,xmm6
00007ff9`df160dec 488b08          mov     rcx,qword ptr [rax]
00007ff9`df160def 660f69eb        punpckhwd xmm5,xmm3
00007ff9`df160df3 660f6ad1        punpckhdq xmm2,xmm1
00007ff9`df160df7 660f62c5        punpckldq xmm0,xmm5
00007ff9`df160dfb 660fe711        movntdq xmmword ptr [rcx],xmm2

```

## Vulnerability 3
## Product Information
* Plugin: Exr.dll - 4.67.1.0

## File Information
### Extension.
* exr

### File name
* 0003.exr

## Vulnerability description
* When executing certain files in irfanview version 4.67, an access violation occurs in EXR!ReadEXR+0x3df50.

### Vulnerability POC
```
0:000> g
ModLoad: 00007ffb`24870000 00007ffb`248a1000   C:\WINDOWS\System32\IMM32.DLL
ModLoad: 00007ffb`1e880000 00007ffb`1e930000   C:\WINDOWS\system32\uxtheme.dll
ModLoad: 00007ffb`23140000 00007ffb`234cd000   C:\WINDOWS\System32\combase.dll
ModLoad: 00007ffb`24cf0000 00007ffb`24e4b000   C:\WINDOWS\System32\MSCTF.dll
ModLoad: 00007ffb`033c0000 00007ffb`03470000   C:\WINDOWS\SYSTEM32\TextShaping.dll
ModLoad: 00007ffb`24810000 00007ffb`2486e000   C:\WINDOWS\System32\SHLWAPI.dll
ModLoad: 00007ffa`e3cf0000 00007ffa`e3d8c000   C:\WINDOWS\system32\IMGSF50Filter_x64.dll
ModLoad: 00007ffb`24270000 00007ffb`24415000   C:\WINDOWS\System32\ole32.dll
ModLoad: 00007ffb`248b0000 00007ffb`248b8000   C:\WINDOWS\System32\PSAPI.DLL
ModLoad: 00007ffb`05210000 00007ffb`05310000   C:\WINDOWS\SYSTEM32\Opengl32.dll
ModLoad: 00007ffb`04d20000 00007ffb`04d4d000   C:\WINDOWS\SYSTEM32\GLU32.dll
ModLoad: 00007ffb`1ea20000 00007ffb`1ea57000   C:\WINDOWS\SYSTEM32\dxcore.dll
ModLoad: 00007ffb`21220000 00007ffb`21238000   C:\WINDOWS\SYSTEM32\kernel.appcore.dll
ModLoad: 00007ffb`22610000 00007ffb`2268b000   C:\WINDOWS\System32\bcryptPrimitives.dll
ModLoad: 00007ffb`24910000 00007ffb`249e7000   C:\WINDOWS\System32\OLEAUT32.dll
ModLoad: 00007ffb`027b0000 00007ffb`028fe000   C:\WINDOWS\SYSTEM32\textinputframework.dll
ModLoad: 00007ffb`051a0000 00007ffb`05209000   C:\WINDOWS\system32\Oleacc.dll
ModLoad: 00007ff9`de4c0000 00007ff9`de81f000   C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
(a7d8.7918): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\devCode\bughunt\winafl\zoc_teamProject_fuzz\irfanview\11_exe\iview467_x64_all\Plugins\EXR.DLL
EXR!ReadEXR+0x3df50:
00007ff9`de4ffe40 668907          mov     word ptr [rdi],ax ds:00000234`aa95adc6=????

0:000> t
(a7d8.7918): Access violation - code c0000005 (!!! second chance !!!)
EXR!ReadEXR+0x3df50:
00007ff9`de4ffe40 668907          mov     word ptr [rdi],ax ds:00000234`aa95adc6=????

0:000> r
rax=0000000000003c00 rbx=00000234aa95af46 rcx=0000000000000000
rdx=0000000000003c00 rsi=000000b24bafcfa0 rdi=00000234aa95adc6
rip=00007ff9de4ffe40 rsp=000000b24bafce30 rbp=000000b24bafcec1
 r8=00000234aa95af46  r9=0000000007800000 r10=000000b24bafce54
r11=0000000030303000 r12=4924924924924925 r13=0000000000000001
r14=0000000000000008 r15=0000000000000001
iopl=0         nv up ei ng nz na pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010281
EXR!ReadEXR+0x3df50:
00007ff9`de4ffe40 668907          mov     word ptr [rdi],ax ds:00000234`aa95adc6=????

0:000> kv
 # Child-SP          RetAddr               : Args to Child                                                           : Call Site
00 000000b2`4bafce30 00007ff9`de510041     : 00000000`30303030 000001ec`aa956880 000000b2`4bafd050 00000000`30303030 : EXR!ReadEXR+0x3df50
01 000000b2`4bafcf00 00007ff9`de51764c     : 000001ec`aa95afd0 00007ff9`de510c3b 000001ec`aa9592b0 000001ec`aa95afd0 : EXR!ReadEXR+0x4e151
02 000000b2`4bafcf90 00007ff9`de5173a3     : 00000000`00000000 00007ff9`de516af3 ffffffff`fffffffe 000001ec`50000063 : EXR!ReadEXR+0x5575c
03 000000b2`4bafcfc0 00007ff9`de511848     : 000001ec`aa94c690 000001ec`aa94c690 000001ec`aa956830 00007ff9`de4f5d92 : EXR!ReadEXR+0x554b3
04 000000b2`4bafd010 00007ff9`de5038aa     : 00000000`00000010 000001ec`aa95af80 00000000`00000000 ffffffff`fffffffe : EXR!ReadEXR+0x4f958
05 000000b2`4bafd2f0 00007ff9`de4cdd7e     : 00000001`00000001 00000000`00000000 000000b2`4bafd630 000001ec`aa95adc0 : EXR!ReadEXR+0x419ba
06 000000b2`4bafd330 00007ff9`de4c2572     : 00000000`00000031 00000000`00000031 00000000`00000094 00000000`00000031 : EXR!ReadEXR+0xbe8e
07 000000b2`4bafd3d0 00007ff7`1a95dd0c     : 00000000`00000000 00007ff9`de4c1ef0 000000b2`4bafde50 000000b2`4bafde50 : EXR!ReadEXR+0x682
08 000000b2`4bafd530 00007ff7`1a984ed4     : 000001ec`aa94a7c0 00000000`00001030 00000000`0000007f 00000000`000017b0 : i_view64+0x8dd0c
09 000000b2`4bafdd40 00007ff7`1a983ce8     : 00000000`00000000 00000000`00000000 000000b2`4bafec40 00007ff7`1aaefd40 : i_view64+0xb4ed4
0a 000000b2`4bafeb70 00007ff7`1a956b52     : 00000000`00000384 00000000`00000384 00000000`00000005 00007ff7`1a8d0000 : i_view64+0xb3ce8
0b 000000b2`4baff6d0 00007ff7`1a9e64b0     : 00000000`00000000 00000000`00000000 00000000`0000000a 00007ff7`1a8d0000 : i_view64+0x86b52
0c 000000b2`4baffce0 00007ffb`2449257d     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : i_view64+0x1164b0
0d 000000b2`4baffd20 00007ffb`24f6af28     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x1d
0e 000000b2`4baffd50 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x28

0:000> u
EXR!ReadEXR+0x3df50:
00007ff9`de4ffe40 668907          mov     word ptr [rdi],ax
00007ff9`de4ffe43 4903fe          add     rdi,r14
00007ff9`de4ffe46 483bfb          cmp     rdi,rbx
00007ff9`de4ffe49 76f5            jbe     EXR!ReadEXR+0x3df50 (00007ff9`de4ffe40)
00007ff9`de4ffe4b e996060000      jmp     EXR!ReadEXR+0x3e5f6 (00007ff9`de5004e6)
00007ff9`de4ffe50 f2480f2c4567    cvttsd2si rax,mmword ptr [rbp+67h]
00007ff9`de4ffe56 483bfb          cmp     rdi,rbx
00007ff9`de4ffe59 0f8787060000    ja      EXR!ReadEXR+0x3e5f6 (00007ff9`de5004e6)

```