.code

PEBValue proc
	mov rax, gs:[60h]
	ret
PEBValue endp

checkDebugger proc
	xor eax, eax
	call PEBValue
	movzx eax, byte ptr [rax+2h]
	ret
checkDebugger endp

end