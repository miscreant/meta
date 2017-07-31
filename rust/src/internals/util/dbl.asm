mov rax, qword ptr [rdi]
mov rcx, qword ptr [rdi + 8]
bswap rcx
bswap rax
mov rdx, rax
shld rdx, rcx, 1
add rcx, rcx
sar rax, 63
and eax, 135
xor rax, rcx
bswap rax
bswap rdx
mov qword ptr [rdi], rdx
mov qword ptr [rdi + 8], rax
