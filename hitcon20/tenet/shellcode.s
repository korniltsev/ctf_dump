BITS 64


mov rax, 0x2170000

mov rdi, [rax]
mov [rax], rdi


mov qword [rax+16], rdi
mov rdi, qword [rax+16]
vmovdqu [rax], ymm1



mov qword [rax+16], rdi
vmovdqu ymm0, [rax]
vmovdqa ymm1, ymm0
mov qword [rax+16], 0


mov rax, 0x2170000


; exit
mov rax, 0x3C
syscall




