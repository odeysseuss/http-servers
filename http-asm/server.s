section .data
    sockaddr:
        .family: dw 2
        .port: dw 0x5000
        .addr: dd 0
        .zero: dq 0

section .data
    okresp: db `HTTP/1.0 200 OK\r\n\r\n`
    okresp_len equ $ - okresp
    get_method: db "GET", 0
    post_method: db "POST", 0

section .bss
    req_length resq 1
    req_buffer resb 1024
    filename resb 256
    file_buffer resb 4096
    http_method resb 8
    content_body resb 4096
    content_length resq 1

section .text
    global _start

; strcmp(str1, str2)
strcmp:
    push rbp
    mov rbp, rsp

strcmp_loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne strcmp_nequal
    test al, al
    jz strcmp_equal
    inc rdi
    inc rsi
    jmp strcmp_loop

strcmp_nequal:
    mov eax, 1
    mov rsp, rbp
    pop rbp
    ret

strcmp_equal:
    xor eax, eax ; return 0 (equal)
    mov rsp, rbp
    pop rbp
    ret

; get(src, dest) -> copy filename from req_buffer to filename
get_filename:
    push rbp
    mov rbp, rsp

copy_filename_loop:
    mov al, [rsi]
    cmp al, " "
    je copy_done
    cmp al, 0
    je copy_done
    mov [rdi], al
    inc rsi
    inc rdi
    jmp copy_filename_loop

copy_done:
    mov byte [rdi], 0
    mov rsp, rbp
    pop rbp
    ret

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 41
    syscall

    mov r8, rax ; sock_fd

    ; bind(sock_fd, &sockaddr, 16)
    mov rdi, r8
    mov rsi, sockaddr
    mov rdx, 16
    mov rax, 49
    syscall

    ; listen(sock_fd, 0)
    mov rsi, 0
    mov rax, 50
    syscall

main_loop:
    ; accept(sock_fd, 0, 0)
    mov rdi, r8
    mov rsi, 0
    mov rdx, 0
    mov rax, 43
    syscall

    mov r9, rax ; client_fd

    ; fork(void)
    mov rax, 57
    syscall
    cmp rax, 0
    je child_proc
    jmp parent_proc

child_proc:
    ; close(sock_fd) / listening socket
    mov rdi, r8
    mov rax, 3
    syscall

    ; read(client_fd, req_buffer, 1024)
    mov rdi, r9
    mov rsi, req_buffer
    mov rdx, 1024
    mov rax, 0
    syscall

    mov [req_length], rax

    mov rsi, req_buffer
    mov rdi, http_method

; parse http_method from request
parse_method_loop:
    mov al, [rsi]
    cmp al, " "
    je parse_done
    cmp al, 0
    je parse_done
    mov [rdi], al
    inc rsi
    inc rdi
    jmp parse_method_loop

parse_done:
    mov byte [rdi], 0

    mov rdi, http_method
    mov rsi, get_method
    call strcmp
    test rax, rax
    jz handle_get
    jne handle_post

handle_get:
    lea rsi, [req_buffer + 4]
    mov rdi, filename
    call get_filename

    ; open(filename, O_RDONLY)
    mov rdi, filename
    mov rsi, 0
    mov rax, 2
    syscall

    mov r10, rax ; file_fd

    ; read(file_fd, file_buffer, 4096)
    mov rdi, r10
    mov rsi, file_buffer
    mov rdx, 4096
    mov rax, 0
    syscall

    ; DEBUG: when r11 is used instead of rbx it does not work. WHY?!
    ; DEBUG: instead of writing the read bytes it writes the whole file_buffer
    mov rbx, rax ; bytes_read

    ; close(file_fd)
    mov rax, 3
    syscall

    ; write(client_fd, okresp, okresp_len)
    mov rdi, r9
    mov rsi, okresp
    mov rdx, okresp_len
    mov rax, 1
    syscall

    ; write(client_fd, file_buffer, bytes_read)
    mov rsi, file_buffer
    mov rdx, rbx
    mov rax, 1
    syscall

    jmp child_close

handle_post:
    mov rbx, [req_length]
    mov rdi, req_buffer
    mov rcx, rbx
    sub rcx, 3

find_content:
    cmp byte [rdi], 13
    jne next_byte
    cmp byte [rdi + 1], 10
    jne next_byte
    cmp byte [rdi + 2], 13
    jne next_byte
    cmp byte [rdi + 3], 10
    jne next_byte
    je found_content

next_byte:
    inc rdi
    dec rcx
    jnz find_content

    mov rbx, 0
    mov qword [content_length], 0
    jmp post_resp

found_content:
    add rdi, 4
    mov rax, rdi
    sub rax, req_buffer
    sub rbx, rax

    mov [content_length], rbx

    mov rsi, rdi
    mov rdi, content_body
    mov rcx, rbx
    test rcx, rcx
    jz copy_done

copy_content:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz copy_content

post_resp:
    lea rsi, [req_buffer + 5]
    mov rdi, filename
    call get_filename

    ; open(filename, O_CREAT)
    mov rdi, filename
    mov rsi, 0x41
    mov rdx, 0o777
    mov rax, 2
    syscall

    mov r10, rax ; file_fd

    ; write(file_fd, content_body, bytes_read)
    mov rdi, r10
    mov rsi, content_body
    mov rdx, rbx
    mov rax, 1
    syscall

    ; close(file_fd)
    mov rax, 3
    syscall

    ; write(client_fd, okresp, okresp_len)
    mov rdi, r9
    mov rsi, okresp
    mov rdx, okresp_len
    mov rax, 1
    syscall

    jmp child_close

child_close:
    ; close(client_fd)
    mov rdi, r9
    mov rax, 3
    syscall

    ; exit(0)
    mov rax, 60
    mov rdi, 0
    syscall

parent_proc:
    ; close(client_fd) / close client socket
    mov rdi, r9
    mov rax, 3
    syscall

    jmp main_loop
