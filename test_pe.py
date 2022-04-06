from importlib.metadata import entry_points
import pefile
import pwn

# Calc entry point virtual address = entry_point + image_base


def calc_entry_point_va(pe):
    # Get entry_point and image_base of pe file
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Calc the entry_point_virtual_address = entry_point + image_based
    entry_point_va = entry_point + image_base

    return entry_point_va

# Get the rsrc section


def get_rsrc_section(pe):
    rsrc_section = []
    for section in pe.sections:
        rsrc_section.append([section.Name, hex(section.Misc_VirtualSize), hex(section.VirtualAddress),
                             hex(section.SizeOfRawData), hex(section.PointerToRawData)])

    return rsrc_section[2][2], rsrc_section[2][4]

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
    # Path
    path = 'C:\\Users\\ADmin\\Desktop\\TestPlace\\NOTEPAD.exe'
    pe = pefile.PE(path)

    # Calc the entry_point
    entry_point_va = calc_entry_point_va(pe)
    print('Entry point va: ', hex(entry_point_va))

    # Get the header section of pe file
    rsrc_virtual_address, rsrc_raw_address = get_rsrc_section(pe)
    print("rsrc virtual address: ", rsrc_virtual_address)
    print("rsrc raw address: ", rsrc_raw_address)
    
    # Calc the x, y, z
    
finally:
    print("Done")
