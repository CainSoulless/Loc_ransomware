#pragma once
#include "injection/IInjector.h"

class IShellcodeInjector : public IInjector {
public:
    virtual ~IShellcodeInjector() = default;

    virtual bool InjectInto(PROCESS_INFORMATION& pi, const std::vector<unsigned char>& shellcode) noexcept = 0;
};
