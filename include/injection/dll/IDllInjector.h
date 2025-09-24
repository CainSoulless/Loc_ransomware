#pragma once
#include "injection/IInjector.h"

class IDllInjector : public IInjector {
public:
    virtual ~IDllInjector() = default;

    virtual bool InjectInto(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath) noexcept = 0;
};
