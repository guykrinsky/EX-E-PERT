import socket

IP, PORT = "0.0.0.0", 80
RUTE_DIRECTORY = ".\\wwwroot"
#RUTE_DIRECTORY = "C:\\Users\\User\\source\\repos\\virus\\http_server\\wwwroot"


def get_file_data(url):
    print(f"url to file is: {url}")
    try:
        file_data = open(url, "rb").read()
    except FileNotFoundError:
        print("user request unfound file")
        return None, 0
    return file_data, len(file_data)


def handle_client_request(resource: str, client_socket):
    """ Check the required resource, generate proper HTTP response and send to client"""

    resource = resource.replace("/", "\\")
    # TO DO : add code that given a resource (URL and parameters) generates the proper response
    if resource == '\\':
        url = RUTE_DIRECTORY
    else:
        url = RUTE_DIRECTORY + resource

    # TO DO: read the data from the file
    file_data, length = get_file_data(url)
    if(length == 0):
        return
    response_line = f"HTTP/1.1 200 OK\r\n"
    http_response = response_line + "\r\n"
    print(f"server response is: \n{response_line}")
    client_socket.send(http_response.encode() + file_data)


def validate_http_request(request):
    """ Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL """
    l = request.split()
    # don't sure if need this condition (and request[len(request) - 4:] == "\n\r")
    return l[0] == "GET" and l[2] == "HTTP/1.1", l[1]


def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')
    while True:
        client_request = client_socket.recv(1024).decode()
        print(f"client request is: {client_request}")
        # \r\n is separate the lines in http protocol.
        request_line = client_request.split("\r\n")[0]
        valid_http, resource = validate_http_request(request_line)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: Not a valid HTTP request')
            break


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        # client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)
        print('Closing connection')
        client_socket.close()


if __name__ == '__main__':
    main()
