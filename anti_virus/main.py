import os
import click
import sys

import code_signing.user
import integrity_check
from code_signing import program_vendor
from output_files_name import CLEAR_OUTPUT, DANGEROUS_OUTPUT
import pick

VIRUS_SCANNER_PATH = "virus_scanner.exe"
sys.path.append(os.path.realpath("."))
PICK_INDICATOR = ">"


def print_output():
    with open(DANGEROUS_OUTPUT, "r") as d_file, open(CLEAR_OUTPUT, "r") as c_file:
        for line in d_file:
            click.secho(line, fg="red")
        for line in c_file:
            click.secho(line, fg="green")


@click.group()
def commands():
    pass


@click.command()
@click.argument("directory_path", type=click.Path(exists=True, file_okay=False))
def scan_virus(directory_path):
    """ Search for the virus in specific directory """
    os.system(f"{VIRUS_SCANNER_PATH} {directory_path}")
    print_output()
    click.secho("finished scan.", fg="bright_blue")


@click.command()
@click.argument("directory_path", type=click.Path(exists=True, file_okay=False))
def save_checksums(directory_path):
    """ Save checksums to all files in directory """
    integrity_check.save_checksums(directory_path)
    click.secho("saved checksums.", fg="bright_blue")


@click.command()
def scan_for_changes():
    """ Scan for changes in files with saved checksums. """
    integrity_check.check_files()
    print_output()
    click.secho("scanned changes.", fg="bright_blue")


@click.command()
def get_program():
    """ Get program safety. """
    program_options = program_vendor.get_programs_provided()
    chosen_program, _ = pick.pick(program_options, title="PROGRAM PROVIDED:", indicator=PICK_INDICATOR)
    click.secho(f"chosen program is {chosen_program}", fg="bright_blue")
    code_signing.user.download(chosen_program)


commands.add_command(save_checksums)
commands.add_command(scan_virus)
commands.add_command(scan_for_changes)
commands.add_command(get_program)


def main():
    commands()


if __name__ == "__main__":
    main()
