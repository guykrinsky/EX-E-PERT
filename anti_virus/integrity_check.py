import os
import hashlib
from output_files_name import CLEAR_OUTPUT, DANGEROUS_OUTPUT

# This directory has to be already secured and without viruses.
CHECKSUMS_FILE_NAME = "checksums_file.txt"
ENCRYPTION_KEY = 0x15
SEPARATOR_BYTES = b":::"
DIRECTORY_PROGRAM_TO_INFECT = "C:\\Users\\User\\source\\repos\\virus\\programs_to_infect"


def get_full_path(directory_name, file_name):
    return f"{directory_name}\\{file_name}"


def encrypt(text: bytes):
    """
    This function encrypt text with xor encryption
    """
    return bytes([x ^ ENCRYPTION_KEY for x in text])


def decrypt_line(encrypted_line: bytes):
    # With xor encryption, if you encrypt same text twice, it would decrypt him.
    encrypted_line = encrypted_line[:len(encrypted_line)-1] # remove \n
    file_path, checksum = encrypt(encrypted_line).split(SEPARATOR_BYTES)
    return file_path.decode(), checksum


def decrypt_checksums_file():
    checksums_file = open(CHECKSUMS_FILE_NAME, "rb")
    # directory is stored in first
    directory = checksums_file.readline().decode()
    directory = directory.replace("\n", "") # Remove \n.
    decrypt_checksums_file_dict = {}
    for line in checksums_file.readlines():
        file_path, checksum = decrypt_line(line)
        decrypt_checksums_file_dict[file_path] = checksum
    return directory, decrypt_checksums_file_dict


def check_files():
    with open(DANGEROUS_OUTPUT, "w") as d_file, open(CLEAR_OUTPUT, "w") as c_file:
        directory, decrypt_checksums_file_dict = decrypt_checksums_file()
        print(f"scanning for changes in {directory}")
        for file_name in (get_full_path(directory, x) for x in os.listdir(directory)):
            with open(file_name, 'rb') as sus_file:
                file_as_bytes = sus_file.read()
                checksum = hashlib.md5(file_as_bytes).digest()
                try:
                    if checksum != decrypt_checksums_file_dict[file_name]:
                        d_file.write(f"LOOKOUT!!! {file_name} has been modified.\n")
                    else:
                        c_file.write(f"{file_name} is clear to use\n")
                except KeyError:
                    print("file is not in antivirus database")


def save_checksums(directory: str):
    """
    this function  would save encrypted file's names with their checksums. like this:

    file name: his checksum.

    :return:
    """
    checksums_file = open(CHECKSUMS_FILE_NAME, "wb")
    checksums_file.write(f"{directory}\n".encode())

    for file_name in (get_full_path(directory, x) for x in os.listdir(directory)):
        with open(file_name, 'rb') as secure_file:
            file_as_bytes = secure_file.read()
            checksum = hashlib.md5(file_as_bytes).digest()
            text = f"{file_name}{SEPARATOR_BYTES.decode()}".encode() + checksum  # In bytes.
            encrypted_text = encrypt(text)
            checksums_file.write(encrypted_text)
            checksums_file.write(b"\n")

    checksums_file.close()


def main():
    save_checksums(DIRECTORY_PROGRAM_TO_INFECT)
    check_files()


if __name__ == "__main__":
    main()
