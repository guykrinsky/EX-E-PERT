import os

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import socket
import hashlib

# In this program I switched between the public and private keys.
# The reason for this is that in code signing you should decrypt with the public key.
# And the Cryptome module doesn't support this.

PROGRAMS_PATH = "C:\\Users\\User\\source\\repos\\virus\\copies_of_programs_to_infect"
PROGRAM_PATH = "C:\\Users\\User\\source\\repos\\virus\\copies_of_programs_to_infect\\msgBox2.exe"
PUBLIC_KEY_FILE_NAME = "RSA_public_key.bin"
PRIVATE_KEY_FILE_NAME = "RSA_private_key.bin"

# Random password for saving private key.
SECRET_PASSWORD = "ENCRYPTING_IS_FUN"

# len in  bytes.
PROGRAM_ADDITION_LEN = 256


def get_keys_from_files():
    with open(PRIVATE_KEY_FILE_NAME, "rb") as private_key_file:
        encoded_private_key = private_key_file.read()
        private_key = RSA.import_key(encoded_private_key, SECRET_PASSWORD)

    with open(PUBLIC_KEY_FILE_NAME, "rb") as public_key_file:
        public_key = RSA.import_key(public_key_file.read())

    return public_key, private_key


def save_keys(keys: RSA.RsaKey):
    # Save keys.
    public_key = keys.export_key()
    with open(PUBLIC_KEY_FILE_NAME, "wb") as public_key_file:
        public_key_file.write(public_key)

    private_key = keys.public_key().export_key(passphrase=SECRET_PASSWORD)
    with open(PRIVATE_KEY_FILE_NAME, "wb") as private_key_file:
        private_key_file.write(private_key)


def get_keys():
    # try read keys.
    try:
        public_key, private_key = get_keys_from_files()
        print("got keys")

    # generate keys.
    except FileNotFoundError:
        key_pair = RSA.generate(2048)
        save_keys(key_pair)
        # Get keys after generate them
        public_key, private_key = get_keys_from_files()

    return public_key, private_key


def get_programs_provided():
    return os.listdir(PROGRAMS_PATH)


def encrypt_msg(key, msg):
    encryptor = PKCS1_OAEP.new(key)
    encrypted = encryptor.encrypt(msg)
    print(f"encrypted msg is {encrypted}")
    return encrypted


def get_program_with_signture(program_name, private_key):
    with open(program_name, "rb") as program_file:
        program = program_file.read()
        checksum = hashlib.md5(program).digest()
        program_addition = encrypt_msg(private_key, checksum)
        return program, program_addition


def main():
    public_key, private_key = get_keys()
    # Tcp connection.
    with socket.socket() as server_socket:
        # ip 0.0.0.0 is working for inside packets either
        server_socket.bind(("0.0.0.0", 8820))
        server_socket.listen()
        print(f"server is up")
        while True:
            client_socket, client_address = server_socket.accept()

            program_name_len = int(client_socket.recv(2).decode())
            program_name = client_socket.recv(program_name_len).decode()
            print(f"user asking for {program_name} app")

            program, program_addition = get_program_with_signture(f"{PROGRAMS_PATH}\\{program_name}", private_key)
            program_len = str(len(program)).zfill(10)
            client_socket.send(program_len.encode())
            client_socket.send(program)
            client_socket.send(program_addition)

            print(f"sent app with addition successfully")
            client_socket.close()


if __name__ == "__main__":
    main()
