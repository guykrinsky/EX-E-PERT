#include <windows.h>
#include <stdio.h>
#include <fileapi.h>
#include "return_codes.h"
#include <stdbool.h>
#include <conio.h>

#define FILE_PATH "file.txt"
#define SYS_CALL_SUCCSSES 0
#define TURN_PRINTABLE_SPACE(c) c = c == '\r' ? '\n' : c

int main(int argc, char** argv)
{
	FILE* output_file = NULL;
	return_codes_t result = RC__UNINSTALLIZED;
	char c = '\0';
	result = fopen_s(&output_file, FILE_PATH, "a");
	if (result != RC__SUCCESS)
	{
		perror("error open file");
		return (int)result;
	}
	while (true)
	{
		if (_kbhit())
		{
			// button is being pressed.
			c = _getch();
			TURN_PRINTABLE_SPACE(c);
			putchar(c);
			fputc(c, output_file);
		}
	}
	return 0;
}