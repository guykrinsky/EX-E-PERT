import socket

# Listen to all of the cumper's network card.
IP_ADDRESS = "0.0.0.0"
PORT_NUMBER = 4444

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((IP_ADDRESS, PORT_NUMBER))
        while True:
            data, client_address = server_socket.recvfrom(1024)
            print(f"message is {data.decode()} from {client_address}")


if __name__ == "__main__":
    main()