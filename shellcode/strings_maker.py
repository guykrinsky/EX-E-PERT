import sys


def main():
    sys.argv.remove(sys.argv[0])
    strings_list = sys.argv
    for string in strings_list:
        str_list = list(string)
        str_list.append(0)
        output = str(str_list)
        output = output.replace("[", "{")
        output = output.replace("]", "}")
        print(output)

if __name__ == "__main__":
    main()