import socket
import hashlib
from code_signing import program_vendor
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from output_files_name import *

# program will be saved as this name in computer.
PROGRAM_NAME = "example.exe"


class ProgramHasBeenModified(Exception):
    pass


def get_key():
    with open(f"code_signing\\{program_vendor.PUBLIC_KEY_FILE_NAME}", "rb") as public_key_file:
        public_key = RSA.import_key(public_key_file.read())
    return public_key


def is_program_valid(program_signature, program_in_bytes):
    checksum = hashlib.md5(program_in_bytes).digest()
    public_key = get_key()
    checksum2 = decrypt_msg(public_key, program_signature)
    return checksum2 == checksum


def decrypt_msg(key, enc_msg):
    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(enc_msg)
    return decrypted


def download(app_name: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(("127.0.0.1", 8820))

        # Send len of the app name to server.
        client_socket.send(str(len(app_name)).zfill(2).encode())
        client_socket.send(app_name.encode())

        program_len = int(client_socket.recv(10).decode())
        program_in_bytes = client_socket.recv(program_len)
        program_signature = client_socket.recv(program_vendor.PROGRAM_ADDITION_LEN)

        if is_program_valid(program_signature, program_in_bytes):
            with open(PROGRAM_NAME, "wb") as program_file, open(CLEAR_OUTPUT, "w") as output:
                program_file.write(program_in_bytes)
                output.write(f"program is valid. and saved under the name {PROGRAM_NAME}\n")

        else:
            with open(DANGEROUS_OUTPUT, "w") as output:
                output.write("OH NO.. PROGRAM HAS BEEN MODIFIED\n")
