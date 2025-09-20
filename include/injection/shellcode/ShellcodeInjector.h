#pragma once
#include "injection/shellcode/IShellcodeInjector.h"

class ShellcodeInjector : public IShellcodeInjector {
public:
	ShellcodeInjector() noexcept;
	~ShellcodeInjector() override = default;

	bool InjectInto(PROCESS_INFORMATION& pi, const std::vector<unsigned char>& shellcode) noexcept override;
	BOOL GetThreadContext();

private:
	CONTEXT _GetProcessContext(HANDLE hThread);
	std::vector<unsigned char> shellcode;
	BOOL threadContext = false;
};


