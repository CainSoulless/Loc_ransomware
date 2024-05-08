.code

TEBValue proc
	mov rax, qword ptr gs:[30]
	ret
TEBValue endp

ErrorValue proc
	xor eax, eax
	call TEBValue
	mov eax, dword ptr [rax+68h]
	ret
ErrorValue endp
end