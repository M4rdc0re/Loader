.data
	id DWORD 000h
	jmptofake QWORD 00000000h

.code 

	setup PROC
		mov id, 000h
		nop							; Obfuscation
		and eax, eax				; Obfuscation
		nop							; Obfuscation
		xor rax, rax				; Obfuscation
		nop							; Obfuscation
		mov id, ecx
		and rbx, rbx				; Obfuscation
		mov jmptofake, 00000000h
		nop							; Obfuscation
		xor rax, rax				; Obfuscation
		mov jmptofake, rdx
		nop							; Obfuscation
		ret
	setup ENDP

	executioner PROC
		mov r10, rcx
		nop							; Obfuscation
		xor rax, rax				; Obfuscation
		nop							; Obfuscation
		mov eax, id
		nop							; Obfuscation
		and eax, eax				; Obfuscation
		nop							; Obfuscation
		jmp jmptofake
		nop							; Obfuscation
		ret
	executioner ENDP
end
