import pefile


def get_virtual_address(pe):
    for section in pe.sections:
        print(section.Name, hex(section.VirtualAddress),
              hex(section.Misc_VirtualSize), hex(section.SizeOfRawData))
        
try:
    path = 'C:\\Users\\ADmin\\Desktop\\TestPlace\\NOTEPAD.exe'
    pe = pefile.PE(path)

    # Get entry_point and image_base of pe file
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Calc the entry_point_virtual_address = entry_point + image_based
    entry_point_va = entry_point + image_base

    # print(pe.get_memory_mapped_image()[entry_point:entry_point+100])
    print('Entry point va: ', hex(entry_point_va))
    
    get_virtual_address(pe)

# except :
#    pass

finally:
    print("Done")
