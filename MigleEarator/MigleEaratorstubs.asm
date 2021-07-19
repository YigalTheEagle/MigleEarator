.code

EXTERN SW2_GetSyscallNumber: PROC

NtResumeThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01A3D548Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResumeThread ENDP

NtSuspendThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 072C86E77h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSuspendThread ENDP

NtOpenThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0983C8A85h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenThread ENDP

NtMapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C089E259h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapViewOfSection ENDP

NtCreateSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04303459Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSection ENDP

NtOpenProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08105646Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcess ENDP

NtSetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 013BF4314h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetContextThread ENDP

NtGetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C85BC6E9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetContextThread ENDP

end