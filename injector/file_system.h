#pragma once
#include <Windows.h>
bool get_suitable_file(char*, int, char[MAX_PATH]);
void* read_entire_file(char*, int*, int*);
