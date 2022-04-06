from importlib.metadata import entry_points
import pefile
import pwn
import os
import mmap

# Calc entry point virtual address = entry_point + image_base

# Path to pe file
path = 'C:\\Users\\ADmin\\Desktop\\TestPlace\\NOTEPAD.exe'
pe = pefile.PE(path)

# Get some info about section
number_of_sections = pe.FILE_HEADER.NumberOfSections
last_section = number_of_sections - 1
file_alignment = pe.OPTIONAL_HEADER.FileAlignment
section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

# New section offset
new_section_offset = (pe.sections[last_section].get_file_offset() + 40)


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
    # STEP 0x01 - Resize the Executable
    # Note: I added some more space to avoid error
    print ("[*] STEP 0x01 - Resize the Executable")

    original_size = os.path.getsize(path)
    print ("\t[+] Original Size = %d" % original_size)
    fd = open(path, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fd.close()

    print ("\t[+] New Size = %d bytes\n" % os.path.getsize(path))
    
    print ("\n[*] STEP 0x02 - Add the New Section Header")
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
    name = ".axc" + (4 * b'\x00')
    
    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name)
    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

finally:
    print("\nDone")
