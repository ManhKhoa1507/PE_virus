mov eax, 0x10E00 ; starting payload
mov ecx, 0xBB ; length of not_encrypted block DYNAMICALLY CHANGING
jmp decryptLoop

decryptLoop:
sub eax, 8        ; move to the next byte
mov ebx,[eax]

xor ebx,  ecx ; decrypt qword
mov qword [eax], ebx
sub ecx, 8
jnz decryptLoop