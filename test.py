 # -*- coding: utf-8 -*-

import pefile
import mmap
import os
import shutil
import struct


def align(value_to_align, alignment):
	return int(((value_to_align + alignment - 1) / alignment) * alignment)


def inject_shellcode(input_name, output_name):

	print "\n\n[*] Injecting shellcode to %s" % input_name
	shutil.copy2(input_name, output_name)

	original_size = os.path.getsize(output_name)
	print "[+] Original Size = %d bytes" % original_size
	fd = open(output_name, 'a+b')
	map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
	map.resize(original_size + 0x1000)
	map.close()
	fd.close()

	print "[+] New Size = %d bytes\n" % os.path.getsize(output_name)

	pe =  pefile.PE(output_name)



	address_of_message_box_w = None
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode('utf-8')
		if dll_name == "USER32.dll":
			for func in entry.imports:
				if func.name.decode('utf-8') == "MessageBoxW":
					address_of_message_box_w = func.address

	if not address_of_message_box_w:
		print "[-] PE file not imported MessageBoxW"
		return False


	print "[*] Address of MessageBoxW = %s" % hex(address_of_message_box_w)


	image_base = pe.OPTIONAL_HEADER.ImageBase
	entry_point_old = pe.OPTIONAL_HEADER.AddressOfEntryPoint


	last_section = pe.sections[-1]

	print "[+] Last section info: %s" % last_section 

	last_section_virtual_offset = last_section.VirtualAddress + last_section.Misc_VirtualSize
	last_section_raw_offset = last_section.PointerToRawData + last_section.SizeOfRawData







	raw_address_of_shell_code = original_size
	raw_address_of_caption = raw_address_of_shell_code + 0x50
	raw_address_of_text = raw_address_of_shell_code + 0x70

	virtual_address_of_caption = raw_address_of_caption - last_section.PointerToRawData + last_section.VirtualAddress + image_base
	virtual_address_of_text = raw_address_of_text - last_section.PointerToRawData + last_section.VirtualAddress + image_base
	new_entry_point = raw_address_of_shell_code - last_section.PointerToRawData + last_section.VirtualAddress + image_base


	entry_point_fix = new_entry_point - image_base
	jump_address = (entry_point_old + image_base - 5 - new_entry_point - 45) & 0xffffffff



	shellcode = '\x33\xC0'
	shellcode += '\x40'
	shellcode += '\x0F\xA2'
	shellcode += '\x0F\xBA\xE1\x1F'
	shellcode += '\x72\x22'
	shellcode += '\x64\xFF\x35\x30\x00\x00\x00'
	shellcode += '\x5A'
	shellcode += '\x80\x7A\x02\x01'
	shellcode += '\x74\x14'
	shellcode += '\x6A\x00'
	shellcode += '\x68' + struct.pack("I", virtual_address_of_caption)
	shellcode += '\x68' + struct.pack("I", virtual_address_of_text)
	shellcode += '\x6A\x00'
	shellcode += '\xFF\x15'
	shellcode += struct.pack("I", address_of_message_box_w)
	shellcode += '\xE9' + struct.pack("I", jump_address)
	shellcode += '\x00' * 30
	shellcode += '\x49\x00\x6e\x00\x66\x00\x6f\x00'
	shellcode += '\x00' * 24
	shellcode += '\x49\x00\x6E\x00\x6A\x00\x65\x00\x63\x00\x74\x00\x65\x00\x64\x00\x20\x00\x62\x00\x79\x00\x20\x00\x31\x00\x37\x00\x35\x00\x32\x00\x31\x00\x31\x00\x31\x00\x34\x00\x20\x00\x2D\x00\x20\x00\x31\x00\x37\x00\x35\x00\x32\x00\x30\x00\x37\x00\x36\x00\x36'




	pe.set_bytes_at_offset(raw_address_of_shell_code, shellcode)

	pe.OPTIONAL_HEADER.AddressOfEntryPoint = entry_point_fix
	last_section.Misc_VirtualSize += 0x1000
	last_section.SizeOfRawData += 0x1000
	pe.OPTIONAL_HEADER.SizeOfImage += 0x1000
	pe.write(output_name)

	print "[+] Inject successfully!!!"
	return True

test_files = [
	'test/calc.exe',
	'test/mspaint.exe',
	'test/notepad.exe',
	'test/spider.exe',
	'test/taskmgr.exe',
	'test/winmine.exe'
]

for input_name in test_files:
	output_name = input_name.replace('.exe', '-injected.exe')
	inject_shellcode(input_name, output_name)