cl /c /Ob3 /GS- shellcode.c
objcopy -O binary shellcode.obj shellcode.bin
