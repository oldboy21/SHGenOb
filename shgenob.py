import os
import subprocess
import sys
import pefile
import glob
import argparse

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'  # Reset to default color


def save_to_file(content, filename):

    try:
        # Determine the full path to the file in the current directory
        current_dir = os.getcwd()
        file_path = os.path.join(current_dir, filename)

        # Determine the mode ('w' for text, 'wb' for binary) based on content type
        mode = 'wb' if isinstance(content, bytes) else 'w'

        # Write the content to the file
        with open(file_path, mode) as file:
            file.write(content)

        print(f"{GREEN}[+] File '{filename}' has been successfully created in the current folder.{RESET}")
        return True

    except Exception as e:
        print(f"{RED}[-] An error occurred while saving the file: {RESET}{str(e)}")
        return False



def cleanup():
    # List of file extensions to delete
    extensions = ['*.asm', '*.exe', '*.obj', '*.lnk']
    
    # Counter for deleted files
    deleted_count = 0

    # Iterate through each extension
    for ext in extensions:
        # Use glob to find all files with the current extension
        files = glob.glob(ext)
        
        # Iterate through found files and delete them
        for file in files:
            try:
                os.remove(file)
                print(f"{GREEN}[+] Deleted: {file}{RESET}")
                deleted_count += 1
            except Exception as e:
                print(f"{RED}[-] Error deleting {file}{RESET}: {str(e)}")

    # Print summary
    print(f"{GREEN}[+] Cleanup complete. {deleted_count} file(s) deleted.{RESET}")

def xor_encrypt(shellcode, key):
    """Encrypt shellcode using XOR with the provided key."""
    encrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(shellcode):
        encrypted.append(byte ^ key[i % key_len])
    return encrypted

def insert_shellcode_into_loader(formatted_shellcode, loader_file='loader.cpp'):
    # Read the existing content of the loader file
    with open(loader_file, 'r') as file:
        lines = file.readlines()

    # Find the insertion points
    start_index = -1
    end_index = -1
    for i, line in enumerate(lines):
        if "// insert shellcode here" in line:
            if start_index == -1:
                start_index = i
            else:
                end_index = i
                break

    if start_index == -1 or end_index == -1:
        raise ValueError(f"{RED}[-] Couldn't find both insertion points in the file.{RESET}")

    # Insert the shellcode
    new_content = lines[:start_index+1] + [formatted_shellcode + "\n"] + lines[end_index:]

    # Write the modified content back to the file
    with open(loader_file, 'w') as file:
        file.writelines(new_content)

    print(f"{GREEN}[+] Shellcode successfully inserted into {loader_file}{RESET}")

def extract_text_section(file_path, key=None):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Locate the .text section
        text_section = None
        for section in pe.sections:
            if section.Name.decode().strip('\u0000') == '.text':
                text_section = section
                break

        if not text_section:
            print(f"{RED}[-]  Error: .text section not found in the PE file.{RESET}")
            return

        # Extract the raw bytes from the .text section
        text_bytes = text_section.get_data()

        # Remove trailing null bytes
        text_bytes = text_bytes.rstrip(b'\x00')

        # encrypting the shellcode with provided XOR key if required
        if key:
            text_bytes = xor_encrypt(text_bytes,key)

        # Format the bytes as a C-style byte array with 16 bytes per line
        hex_lines = []
        for i in range(0, len(text_bytes), 16):
            line = ', '.join(f'0x{byte:02X}' for byte in text_bytes[i:i+16])
            hex_lines.append(f"\t{line}")
        formatted_output = "unsigned char text_section[] = {\n" + ",\n".join(hex_lines) + "\n\t};\n"

        
        return formatted_output

    except FileNotFoundError:
        print(f"{RED}[-]  Error: File not found: {file_path}{RESET}")
    except pefile.PEFormatError:
        print(f"{RED}[-]  Error: The file is not a valid PE file: {file_path}{RESET}")
    except Exception as e:
        print(f"{RED}[-]  Error: An unexpected error occurred: {e}{RESET}")
    finally:
        if pe:
            pe.close()

def find_file(root_dir, file_name):
    for root, dirs, files in os.walk(root_dir):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

def run_command_with_vcvars(command, vcvars_path):
    full_command = f'"{vcvars_path}" && {command}'
    print(f"{GREEN}[+] Runnning: {full_command}{RESET}")
    return subprocess.run(full_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def compile_cpp_file(cpp_file, vcvars_path, output_exe=None):
    if not os.path.exists(cpp_file):
        raise FileNotFoundError(f"{RED}[-]  C++ file not found: {cpp_file}{RESET}")

    if output_exe is None:
        output_exe = os.path.splitext(cpp_file)[0] + ".exe"

    compile_command = f'cl /EHsc /W4 /GS- /Fe:"{output_exe}" "{cpp_file}"'
    
    try:
        result = run_command_with_vcvars(compile_command, vcvars_path)
        print(f"{GREEN}[+] Executable created: {output_exe}{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]  Compilation failed with error code {e.returncode}{RESET}")
        print(e.output)
        return False

def modify_asm_file(asm_file):
    with open(asm_file, 'r') as f:
        lines = f.readlines()

    # Remove INCLUDELIB lines
    lines = [line for line in lines if 'INCLUDELIB LIBCMT' not in line and 'INCLUDELIB OLDNAMES' not in line]

    # Add AlignRSP procedure
    align_rsp_proc = '''AlignRSP PROC
    push rsi
    mov rsi, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 020h
    call main
    mov rsp, rsi
    pop rsi
    ret
AlignRSP ENDP
'''
    # Find the first occurrence of '_TEXT SEGMENT'
    text_segment_index = next((i for i, line in enumerate(lines) if '_TEXT\tSEGMENT' in line), -1)
    if text_segment_index != -1:
        lines.insert(text_segment_index + 1, align_rsp_proc)
    else:
        print(f"{RED}[-]  Error: '_TEXT SEGMENT' not found. AlignRSP procedure not added.{RESET}")

    # Remove pdata and xdata segments
    new_lines = []
    skip_segment = False
    for line in lines:
        if any(x in line for x in ['pdata\tSEGMENT', 'pdata\tENDS', 'xdata\tSEGMENT', 'xdata\tENDS']):
            skip_segment = 'ENDS' not in line
            continue
        if not skip_segment:
            new_lines.append(line)

    # Modify gs:96 line
    new_lines = [line.replace('mov\trax, QWORD PTR gs:96', 'mov\trax, QWORD PTR gs:[96]') for line in new_lines]

    with open(asm_file, 'w') as f:
        f.writelines(new_lines)



def main(cpp_file,args):

    vs_path = r"C:\Program Files\Microsoft Visual Studio\2022\Community"

    # Find vcvars64.bat
    vcvars_path = find_file(vs_path, "vcvars64.bat")
    if not vcvars_path:
        print(f"{RED}[-]  Error: vcvars64.bat not found{RESET}")
        return

    # Run cl.exe
    cl_command = f'cl.exe /c /FA /GS- "{cpp_file}"'
    try:
        result = run_command_with_vcvars(cl_command, vcvars_path)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]  Error running cl.exe:{RESET} {e}")
        print(f"{RED}[-]  Command output:{RESET} {e.output}")
        return

    # Modify ASM file
    asm_file = os.path.splitext(cpp_file)[0] + ".asm"
    if not os.path.exists(asm_file):
        print(f"{RED}[-]  Error: ASM file not found: {asm_file}{RESET}")
        return
    modify_asm_file(asm_file)

    # Run ml64.exe
    ml64_command = f'ml64.exe "{asm_file}" /link /entry:AlignRSP'
    try:
        result = run_command_with_vcvars(ml64_command, vcvars_path)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]  Error running ml64.exe:{RESET} {e}")
        print(f"{RED}[-]  Command output:{RESET} {e.output}")
        return

    # Extract and print the .text section
    exe_file = os.path.splitext(cpp_file)[0] + ".exe"
    print(f"{GREEN}[+] Extracting .text section:{RESET}")
    if args.xor_key:
        shellcode_encrypted = extract_text_section(exe_file,args.xor_key)
        save_to_file(shellcode_encrypted, "encrypted_shellcode.txt")

    
    shellcode = extract_text_section(exe_file)
    save_to_file(shellcode, "shellcode.txt")

    if args.skip_loader_test is False:
        # Insert shellcode in loader template
        try:
            insert_shellcode_into_loader(shellcode)
        except FileNotFoundError:
            print(f"{RED}[-]  Error: loader.cpp not found. Please ensure the file exists.{RESET}")
        except ValueError as e:
            print(f"{RED}[-]  Error:{RESET} {str(e)}")

        # Compile loader 
        success = compile_cpp_file("loader.cpp", vcvars_path)
        if success:
            print(f"{GREEN}[+] Compilation successful, running loader.exe to test the generated shellcode{RESET}")
        else:
            print(f"{RED}[-]  Compilation loader failed{RESET}")
            return

        # Run loader with shellcode for testing 
        if not os.path.exists("loader.exe"):
            print(f"{RED}[-]  Error: EXE Loader file not found{RESET}")
            return
        try:
            subprocess.run(["cmd.exe", "/c", "loader.exe"], check=True)
            print(f"{GREEN}[+] Executable loader ran successfully.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[-]  Error running the executable: {RESET} {e}")

    
    # Run the clean up if everything went ok
    if args.debug == False:
        cleanup()
    else:
        print(f"{GREEN}[+] Skipping the cleanup, check intermediary files in the current folder{RESET}")


if __name__ == "__main__":

    some_ascii_art = r'''
  ____________      ________               ___________    
 /   _____/|  |__  /  _____/  ____   ____  \_____  \_ |__  
 \_____  \ |  |  \/   \  ____/ __ \ /    \  /   |   \| __ \
 /        \|   Y  \    \_\  \  ___/|   |  \/    |    \ \_\ \
/_______  /|___|  /\______  /\___  >___|  /\_______  /___  /
        \/      \/        \/     \/     \/         \/    \/
    '''
    
    print(some_ascii_art)
    print("\tShellcode generator from PIC C code by Oldboy21")
    print("\n\n")
    parser = argparse.ArgumentParser(description="Generate Shellcode from C file.")
    parser.add_argument('--code-file','-cf', type=str, required=True, help='Path to the main.c file that contains the PIC code to transform to shellcode')
    parser.add_argument('--debug', '-d', action='store_true',default=False, help='Enable debug mode, if enabled the cleanup will be skipped')
    parser.add_argument('--xor-key', '-xk', type=str, help='(Only if you need to encrypt the shellcode) XOR key in format AA,BB,...')
    parser.add_argument('--skip-loader-test', '-slt', action='store_true', default=False, help="Skip the test with the loader.cpp template")
    args = parser.parse_args()

    # Process XOR key
    if args.xor_key:
        try:
            args.xor_key = [int(x, 16) for x in args.xor_key.split(',')]
        except ValueError:
            print(f"{RED}[-]  Error: Invalid XOR key format. Use format like AA,BB{RESET}")
            sys.exit(1)
    main(args.code_file,args)