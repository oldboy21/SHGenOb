# SHGenOB: Shellcode Generator from PIC C Code

## Introduction

SHGenOB is a Python-based tool designed to generate shellcode from Position Independent Code (PIC) written in C. It automates the process of compiling C code, extracting the .text section, and optionally encrypting the resulting shellcode using XOR encryption.

This project is based entirely on [this](https://raw.githubusercontent.com/vxunderground/VXUG-Papers/main/From%20a%20C%20project%20through%20assembly%20to%20shellcode.pdf) by [hasherezade](https://x.com/hasherezade).

## Position Independent Code (PIC)

**Important Note for SHGenOB Users**: For this shellcode generation tool to work correctly, the C code in the input file must be written as Position Independent Code (PIC). The tool assumes that the provided code adheres to PIC principles and characteristics as described below.

Position Independent Code (PIC) is a type of machine code that can be executed regardless of its absolute memory address. This characteristic makes PIC particularly useful in creating shellcode, shared libraries, and certain types of malware. Key features of PIC include:

- **Address Independence**: PIC can run correctly regardless of where it's loaded in memory.
- **No Fixed Memory References**: It avoids using absolute addresses, instead relying on relative addressing or other techniques to reference memory locations.
- **Self-Contained**: PIC typically includes all necessary data within the code itself, reducing external dependencies.
- **Stack-Strings**: Declaring strings as array of chars forces the compiler to push them in the stack and not in the .data or .pdata section of the PE file
- **Relocation-Free**: It doesn't require the loader to perform relocations, making it faster to load and execute.
- **Smaller Size**: PIC often results in smaller binary sizes compared to position-dependent code.
- **Register-Relative Addressing**: It frequently uses register-relative addressing to access data and perform jumps.
- **Use of Offsets**: Instead of absolute addresses, PIC uses offsets from the current instruction pointer.
- **Platform-Specific Techniques**: Different CPU architectures may require different techniques to achieve position independence.

PIC is essential in scenarios where the exact load address of the code is not known in advance, making it a crucial concept in shellcode development and certain areas of systems programming. When using SHGenOB, ensure that your input C code follows these PIC principles to generate effective and reliable shellcode.


## Features

- Compiles PIC C code using Microsoft Visual Studio tools
- Extracts the .text section from the compiled executable
- Optionally encrypts the shellcode using XOR encryption
- Inserts the generated shellcode into a loader template
- Compiles and tests the loader with the generated shellcode
- Supports debug mode for intermediate file inspection
- Cleans up intermediate files after successful execution

## Requirements

- Windows operating system
- Python 3.6 or higher
- Microsoft Visual Studio 2022 Community Edition (or compatible version)
- The following Python packages:
  - pefile
  - argparse
- A C compiler (cl.exe) and assembler (ml64.exe) from Visual Studio
- vcvars64.bat file from Visual Studio (for setting up the compilation environment)

## Installation

1. Install Python 3.6 or higher from [python.org](https://www.python.org/downloads/)
2. Install Microsoft Visual Studio 2022 Community Edition
3. Install required Python packages:

`pip install pefile argparse`

4. Clone or download this repository to your local machine

## Usage

Run the script from the command line with the following syntax:

`python shgenob.py --code-file <path_to_c_file> [--debug] [--xor-key ]`

Arguments:
- `--code-file` or `-cf`: (Required) Path to the main.c file containing the PIC code
- `--debug` or `-d`: (Optional) Enable debug mode (skips cleanup of intermediate files)
- `--xor-key` or `-xk`: (Optional) XOR key for encrypting the shellcode (format: AA,BB,CC)

Example:

`python shgenob.py --code-file main.c --debug --xor-key AA,BB,CC`


## Function Descriptions

1. `save_to_file(content, filename)`: Saves given content to a file in the current directory
2. `cleanup()`: Deletes intermediate files (.asm, .exe, .obj, .lnk) in the current directory
3. `xor_encrypt(shellcode, key)`: Encrypts shellcode using XOR with the provided key
4. `insert_shellcode_into_loader(formatted_shellcode, loader_file)`: Inserts shellcode into the loader template
5. `extract_text_section(file_path, key)`: Extracts the .text section from a PE file and optionally encrypts it
6. `find_file(root_dir, file_name)`: Searches for a file in the given directory and its subdirectories
7. `run_command_with_vcvars(command, vcvars_path)`: Runs a command with Visual Studio environment variables set
8. `compile_cpp_file(cpp_file, vcvars_path, output_exe)`: Compiles a C++ file using Visual Studio compiler
9. `modify_asm_file(asm_file)`: Modifies the generated assembly file for shellcode compatibility
10. `main(cpp_file, args)`: Main function that orchestrates the shellcode generation process

## Workflow

1. Parse command-line arguments
2. Locate Visual Studio tools (vcvars64.bat, cl.exe, ml64.exe)
3. Compile the input C file to assembly
4. Modify the generated assembly file
5. Assemble the modified assembly file
6. Extract the .text section from the resulting executable
7. Optionally encrypt the extracted shellcode
8. Save the shellcode to a file
9. Insert the shellcode into a loader template
10. Compile the loader
11. Test the loader with the generated shellcode
12. Clean up intermediate files (unless in debug mode)

## Debugging

Use the `--debug` flag to skip the cleanup process and inspect intermediate files. This is useful for troubleshooting and understanding the shellcode generation process.

## Security Considerations

- This tool is intended for educational and authorized testing purposes only
- Generated shellcode may be flagged by antivirus software
- Use encryption (XOR key) to obfuscate the shellcode, but note that this is a basic form of obfuscation
- Ensure you have permission to use this tool on the target systems

## Limitations

- Currently only supports Windows and Microsoft Visual Studio toolchain
- Limited error handling for some edge cases
- XOR encryption is a basic form of obfuscation and may not be sufficient for all use cases

## Contributing

Contributions to improve SHGenOB are welcome. Please follow these steps:
1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

