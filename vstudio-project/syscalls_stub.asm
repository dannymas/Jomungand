.data

	wSyscall	DWORD	0h
	pJmpAddr	QWORD	0h

.code
	ntPrepare PROC
		mov wSyscall, ecx
		mov pJmpAddr, rdx
		ret
	ntPrepare ENDP

	ntCall PROC

		mov rax, rcx
		mov r10, rax
		mov eax, wSyscall

		jmp pJmpAddr

		ret

	ntCall ENDP

end