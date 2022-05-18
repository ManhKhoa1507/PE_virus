import re
import random


class SimplePoly:
    """
    Polymorphic class
    """

    def __init__(self, path):
        # Get input file
        # Init registers and stack
        self.stack_register = None
        self.add_sub_register = None
        self.border_pos = None
        self.all_registers_lst = ['edx', 'eax', 'ecx', 'esi', 'edi', 'ebx','ebp', 'esp']
        self.path = path

        # List of intrustions
        self.content = list()
        self.mov_xor_jmp_je_jk_lst = list()
        self.add_sub_lst = list()
        self.add_sub_lst_im = list()
        self.add_sub_lst_reg = list()
        self.register_lst = list()
        self.mul_lst = list()
        self.cmp_lst = list()

    def reader(self):
        # Read content of asm file
        with open(self.path) as f:
            for line in f:
                self.content.append(line.strip().split('\n'))

    def parser(self, word, lst):
       # Find all command in asm file
        for i in range(len(self.content)):
            if re.match(word, self.content[i][0]):
                lst.append(self.content[i])

    def parser_register(self):
        # Find all register in asm file -> self_all_registers_lst
        for i in range(len(self.content)):
            length = len(self.content[i][0])
            register = str()

            while length != 0:
                if self.content[i][0][length - 1] == ',':
                    while self.content[i][0][length - 1] != ' ' and self.content[i][0][length - 1] != '\t':
                        length -= 1
                        if self.content[i][0][length - 1].isalnum():
                            register += self.content[i][0][length - 1]
                        else:
                            break
                    break
                length -= 1

            if register:
                register = register[::-1]
                self.register_lst.append(register)

        # List all register
        self.register_lst = list(set(self.register_lst))

        # Remove trash register
        trash = list()
        for i in range(len(self.register_lst)):
            if len(self.register_lst[i]) > 3 or len(self.register_lst[i]) < 2:
                trash.append(self.register_lst[i])
        for i in range(len(trash)):
            self.register_lst.remove(trash[i])

    def parser_commands(self):
        # Find all mov, cmp, jmp, je, jk commands
        self.parser(r"mov|jmp|je|jk|xor", self.mov_xor_jmp_je_jk_lst)

    def parser_add_sub(self):
        # Find add and sub commands
        self.parser(r"add|sub", self.add_sub_lst)

    def parser_cmp(self):
        # Find cmp commands
        self.parser(r"cmp", self.cmp_lst)

    def parser_mul(self):
        # Find all mul and nov commands
        self.parser(r"mul", self.mul_lst)

        for i in range(len(self.mul_lst)):
            index = self.content.index(self.mul_lst[i])

            self.mul_lst.insert(i, self.content[index - 1])
            self.mul_lst.insert(i, self.content[index - 2])

    def set_border(self):
        # Detect first command in asm code
        for i in range(len(self.content)):
            if self.content[i] in self.mov_xor_jmp_je_jk_lst or self.content[i] in self.cmp_lst or \
                    self.content[i] in self.mul_lst or self.content[i] in self.add_sub_lst:
                self.border_pos = self.content[i]
                break

    def classification_add_sub(self):
        # Divide to different lists add and sub command, add sub with immediate and add with register
        for i in range(len(self.add_sub_lst)):
            if re.search(r', ?[0-9]+', self.add_sub_lst[i][0]):
                self.add_sub_lst_im.append(self.add_sub_lst[i])

            else:
                self.add_sub_lst_reg.append(self.add_sub_lst[i])

    @staticmethod
    def number_division(number):
        # Return random number where param number is sup
        return random.randrange(number)

    @staticmethod
    def line_maker(line, number, reverse=False):
        # Generate new line of asm code with add or sub with new numeric value
        new_line = str()
        i = 0
        while line[i] != ',':
            new_line += line[i]
            i += 1
        new_line += ','
        new_line += str(number)

        # Create sub
        if reverse and new_line[0] == 'a':
            new_line = list(new_line)
            new_line[0], new_line[1], new_line[2] = 's', 'u', 'b'
            new_line = ''.join(new_line)

        # Create add
        elif reverse and new_line[0] == 's':
            new_line = list(new_line)
            new_line[0], new_line[1], new_line[2] = 'a', 'd', 'd'
            new_line = ''.join(new_line)

        return new_line

    def nope_adder(self, element):
        # Add nop command
        index = self.content.index(element)
        self.content.insert(index, ['nop'])

    def division_adder_im(self, element):
        # Extract number from a line and choose how to divide it
        length = len(element[0])
        number = str()
        exact_number = str()

        while element[0][length - 1] != ',':
            number += element[0][length - 1]
            length -= 1
        number = number.split()

        for i in range(len(number)):
            if number[i].isdecimal():
                exact_number = number[i]
                break

        number = int(exact_number[::-1])
        div = self.number_division(number)

        # Make random choice
        choice = random.choice([1, 2, 3])

        if choice == 1:
            self.division_adder_im_2(element, div, number)

        elif choice == 2:
            self.division_adder_sub(element, div, number)

        else:
            self.division_adder_im_3(element, div, number)

    def division_adder_im_2(self, element, div, number):
        # Make add, or sub eax 8 -> add eax 5, add eax 3
        new_line = self.line_maker(element[0], div)

        self.content.insert(self.content.index(element), [new_line])
        self.content[self.content.index(element)] = \
            [self.line_maker(element[0], number - div)]

    def division_adder_im_3(self, element, div, number):
        # Make add, or sub eax 8 -> add eax 5, add eax 1, add eax 2
        if div == 0:
            new_div = 0
        else:
            new_div = self.number_division(div)

        self.content.insert(self.content.index(element), [
                            self.line_maker(element[0], new_div)])

        self.content.insert(self.content.index(element), [
                            self.line_maker(element[0], div - new_div)])

        self.content[self.content.index(element)] = \
            [self.line_maker(element[0], number - div)]

    def division_adder_sub(self, element, div, number):
        # Make command from sub
        new_div = random.randint(number + 1, number + div + 1)

        self.content.insert(self.content.index(element), [
                            self.line_maker(element[0], new_div)])

        self.content[self.content.index(element)] = \
            [self.line_maker(element[0], new_div - number, True)]

    def add_sub_adder(self, element):
        # Function which add two lines with add some number to eax and sub this number from eax register.
        reg = str()
        if not self.add_sub_register:
            for i in range(len(self.all_registers_lst)):
                if self.all_registers_lst[i] not in self.register_lst\
                        and self.all_registers_lst[i] != self.stack_register:
                    reg = self.all_registers_lst[i]
                    self.add_sub_register = self.all_registers_lst[i]
                    break
        else:
            reg = self.add_sub_register

        index = self.content.index(element)
        number = self.number_division(10)

        self.content.insert(index, ['sub {}, {}'.format(reg, str(number))])
        self.content.insert(index, ['add {}, {}'.format(reg, str(number))])

    def stack_adder(self, element):
        # Add asm pop and push 
        reg = str()
        if not self.stack_register:
            for i in range(len(self.all_registers_lst)):
                if self.all_registers_lst[i] not in self.register_lst\
                        and self.add_sub_register != self.all_registers_lst[i]:
                    reg = self.all_registers_lst[i]
                    self.stack_register = self.all_registers_lst[i]
                    break
        else:
            reg = self.stack_register
            
        index = self.content.index(element)
        self.content.insert(index, [f'pop {reg}'])
        self.content.insert(index, [f'push {reg}'])

    def stack_nop_adder(self, element):
        # Add nop in stack between push and pop
        reg = str()
        if not self.stack_register:
            for i in range(len(self.all_registers_lst)):
                if self.all_registers_lst[i] not in self.register_lst \
                        and self.add_sub_register != self.all_registers_lst[i]:
                    reg = self.all_registers_lst[i]
                    self.stack_register = self.all_registers_lst[i]
                    break
        else:
            reg = self.stack_register
            
        index = self.content.index(element)
        self.content.insert(index, [f'pop {reg}'])
        self.content.insert(index, ['nop']) 
        self.content.insert(index, [f'push {reg}'])

    def swap_of_reg(self, element):
       # Swap register of cmp 
        if len(element[0]) > 16:
            return 0
        
        l_reg = str()
        f_reg = str()  
        length = len(element[0]) - 1
        
        while element[0][length] != ',':
            l_reg += element[0][length]
            length -= 1
            
        while element[0][length] != 'p':
            f_reg += element[0][length]
            length -= 1
            
        if l_reg[-1] == ' ':
            l_reg = l_reg[:-1]
            
        l_reg = l_reg[::-1]
        
        if f_reg[-1] == ' ':
            f_reg = f_reg[:-1]
            
        f_reg = f_reg[::-1]
        f_reg = f_reg[:-1]
        
        if f_reg.isdecimal() or l_reg.isdecimal():
            return 0
        self.content[self.content.index(element)] = [f"cmp {l_reg}, {f_reg}"]

    def commands_transformer(self):
        # Modify every mov, jmp, jk, je command.
        for i in range(len(self.mov_xor_jmp_je_jk_lst)):
            # Make random choice
            choice = random.choice([1, 2, 3, 4])
            if choice == 1:
                self.nope_adder(self.mov_xor_jmp_je_jk_lst[i])
            elif choice == 2:
                self.add_sub_adder(self.mov_xor_jmp_je_jk_lst[i])
            elif choice == 3:
                self.stack_nop_adder(self.mov_xor_jmp_je_jk_lst[i])
            else:
                self.stack_adder(self.mov_xor_jmp_je_jk_lst[i])

    def add_sub_transformer(self):
        # Modify every add and sub command.
        self.set_border()
        
        for i in range(len(self.add_sub_lst_im)):
            choice = random.choice([1, 2, 3])
            if choice == 1:
                self.nope_adder(self.add_sub_lst_im[i])
            elif choice == 2:
                self.stack_adder(self.add_sub_lst_im[i])
            else:
                self.division_adder_im(self.add_sub_lst_im[i])
        for i in range(len(self.add_sub_lst_reg)):
            choice = random.choice([1, 2, 3])
            if choice == 1:
                self.nope_adder(self.add_sub_lst_reg[i])
            elif choice == 2:
                self.stack_adder(self.add_sub_lst_reg[i])
            else:
                self.add_sub_adder(self.add_sub_lst_reg[i])

    def mul_transform(self):
        # Function to transform a mul command.
        for i in range(2, len(self.mul_lst), 3):
            choice = random.choice([i - 1, i - 2])
            element = self.mul_lst[choice]
            length = len(element[0])
            number = str()
            register = str()
            
            while element[0][length - 1] != ',':
                number += element[0][length - 1]
                length -= 1
                
            number = int(number[::-1])
            div = self.number_division(number)
            line = self.line_maker(element[0], div)
            self.content[self.content.index(element)] = [line]
            
            while element[0][length - 1] != ' ':
                register += element[0][length - 1]
                length -= 1
                
            register = register[::-1]
            self.content.insert(self.content.index(
                [line]) + 1, ['add {} {}'.format(register, str(number - div))])

    def cmp_transform(self):
        # Function to transform cmp command.

        for i in range(len(self.cmp_lst)):
            choice = random.choice([1, 2, 3])
            choice = 3
            if choice == 1:
                self.nope_adder(self.cmp_lst[i])
            elif choice == 2:
                self.stack_adder(self.cmp_lst[i])
            else:
                self.swap_of_reg(self.cmp_lst[i])

    def polymorphic(self):
        """
        Make code polymorphous and write it to new asm file.
        :return:  None
        """
        self.reader()
        self.parser_add_sub()
        self.parser_mul()
        self.parser_commands()
        self.parser_register()
        self.parser_cmp()
        self.set_border()
        self.classification_add_sub()
        self.commands_transformer()
        self.add_sub_transformer()
        self.mul_transform()
        self.cmp_transform()

        content = str()

        for i in range(len(self.content)):
            content += self.content[i][0]
            if i != len(self.content) - 1:
                content += '\n'
        with open(f"{self.path[:-4]}_pol.asm", 'w') as f:
            f.write(content)


if __name__ == "__main__":
    a = SimplePoly("./src_asm/test.asm")
    a.polymorphic()
    print(a.register_lst)