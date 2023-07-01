#!/usr/bin/env sage

import os
import sys
import sqlite3
import parser
import tempfile
import re
import subprocess
import hashlib
import traceback


def extract_file_with_7z(contianer_path, file_path):
    try:
        output = subprocess.check_output(['7z', 'x', '-so', contianer_path, file_path], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output
    return output


def process_file_contents_with_7z(container_path, file_path, process_func, container_extension=None):
    process_func(extract_file_with_7z(container_path, file_path), file_path, container_extension)


def process_container_with_7z(file_path):
    files = {}
    # Use 7zip to list the contents of the MSI file
    command = ['7z', 'l', '-slt', '-r', '-sdel', '-so', file_path]
    try:
        output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output

    # Parse the output
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        file = {'path': '', 'size': 0, 'packed_size': 0, 'created': '', 'modified': ''}

        if lines[i].startswith('Path ='):
            # Extract the path, size, packed size, created, and modified information
            file['path'] = re.search(r'Path = (.+)', lines[i]).group(1)

            while i < len(lines):
                line = lines[i]
                try:
                    if line.startswith('Size = '):
                        file['size'] = re.search(r'Size = (\d+)', line).group(1)
                    elif line.startswith('Packed Size = '):
                        file['packed_size'] = re.search(r'Packed Size = (\d+)', line).group(1)
                    elif line.startswith('Created = '):
                        file['created'] = re.search(r'Created = (.+)', line).group(1)
                    elif line.startswith('Modified = '):
                        file['modified'] = re.search(r'Modified = (.+)', line).group(1)
                    elif line == "":
                        break
                except AttributeError:
                    i = i

                i += 1

            files[file['path']] = file

        i += 1

    return files


file_prefixes = ['pidgen', 'licdll', 'dpcdll', 'mso', 'msa', 'pidca']


def process_nested_file(temp_container_path, path):
    path_lower = path.lower()
    if any(path_lower.startswith(prefix) for prefix in file_prefixes):
        if path_lower.endswith('dll'):
            compressed_file_data = extract_file_with_7z(temp_container_path, path)
            process_dll(compressed_file_data, path)

        if path_lower.endswith('dl_'):
            compressed_file_data = extract_file_with_7z(temp_container_path, path)
            process_container(compressed_file_data, path, container_extension='.dl_')


def process_container(file_data, file_path, container_extension=None):
    # Create a temporary file
    with tempfile.NamedTemporaryFile(suffix=container_extension, delete=False) as temp_container_file:
        temp_container_path = temp_container_file.name
        temp_container_file.write(file_data)
        temp_container_file.close()

    files = process_container_with_7z(temp_container_path)

    if container_extension == '.msi':
        for path, file in files.items():
            process_nested_file(temp_container_path, path)
            if path.lower().startswith('binary.'):
                # Read the contents of files starting with 'Binary.'
                print(f'Parsing MSI Stream Name: {path}')
                process_file_contents_with_7z(temp_container_path, path, process_dll)

    if container_extension == '.cab':
        for path, file in files.items():
            process_nested_file(temp_container_path, path)

    if container_extension == '.dl_':
        process_file_contents_with_7z(temp_container_path, file_path, process_dll)

    # Remove the temporary container file
    os.remove(temp_container_path)


def process_dll(file_data, file_path, container_extension=None):
    # Process the DLL file as needed
    print(f'[{file_path}]: Parsing file')

    pidgen_data = parser.pidgen.parse(file_data)
    if pidgen_data != {}:
        print(f'[{file_path}]: Found PIDGEN data')

        sha1 = hashlib.sha1(file_data).hexdigest()
        print(f'[{file_path}]: SHA1: {sha1}')
        print(pidgen_data)

    try:
        dpcll_data = parser.dpcdll.parse(file_data)
        if dpcll_data != {}:
            print(f'[{file_path}]: Found DPCDLL data')

            sha1 = hashlib.sha1(file_data).hexdigest()
            print(f'[{file_path}]: SHA1: {sha1}')
    except ValueError:
        dpcll_data = {}

    if any(file_path.lower().startswith(prefix) for prefix in ['licdll', 'mso.dll', 'msa.dll']):
        print(f'[{file_path}]: Cataloguing a LICDLL type file')

        sha1 = hashlib.sha1(file_data).hexdigest()
        print(f'[{file_path}]: SHA1: {sha1}')


def process_iso(file_path):
    files = process_container_with_7z(file_path)

    for path, file in files.items():
        if path.lower().endswith('.msi'):
            print(f'[{path}]: Processing MSI file')
            process_file_contents_with_7z(file_path, path, process_container, container_extension='.msi')

        if path.lower().endswith('.cab'):
            print(f'[{path}]: Processing CAB file')
            process_file_contents_with_7z(file_path, path, process_container, container_extension='.cab')

        if path.lower().endswith('.dll'):
            print(f'[{path}]: Processing DLL file')
            process_file_contents_with_7z(file_path, path, process_dll)


def process_file_or_folder(path):
    extensions = ['.iso', '.img']
    if os.path.isfile(path):
        print(f'[{path}]: Processing ISO/Disk Image file')
        process_iso(path)

    elif os.path.isdir(path):
        print(f'[{path}]: Recursing through folder')
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.iso'):
                    iso_path = os.path.join(root, file)
                    print(f'Processing ISO file: {iso_path}')
                    process_iso(iso_path)
    else:
        print(f'Invalid file or folder: {path}')


def check_7z_command():
    if sys.platform.startswith('win'):  # Windows
        try:
            # Use the 'where' command to check if '7z' is in the path
            subprocess.check_output(['where', '7z'])
            return True
        except subprocess.CalledProcessError:
            return False
    else:  # Unix-based systems (Linux, macOS, etc.)
        try:
            # Use the 'which' command to check if '7z' is in the path
            subprocess.check_output(['which', '7z'])
            return True
        except subprocess.CalledProcessError:
            return False


# Main function
def main():
    if len(sys.argv) != 3:
        print('Usage: {} <file.iso|folder> <database>'.format(sys.argv[0]))
        print('Parses <file.iso|folder> for various DLLs required for product licensing and activation')
        print('Data is saved to the SQLite3 Database <database> and will be created if it does not exist')
        print('If a <folder> is specified, it will search recursively for files ending in .iso/.img')
        sys.exit(1)

    path = sys.argv[1]
    database = sys.argv[2]

    if not os.path.exists(database):
        conn = sqlite3.connect(database)
        with open('newdb.sql') as f:
            conn.executescript(f.read())
        conn.close()

    conn = sqlite3.connect(database)
    process_file_or_folder(path)
    conn.close()


# Entry point
if __name__ == '__main__':
    if not check_7z_command():
        print('7zip is not in the path, please add the 7z executable to the system path and try again')
    try:
        main()
    except Exception as e:
        print('An error occurred:', e)
        traceback.print_exc()
        sys.exit(1)
