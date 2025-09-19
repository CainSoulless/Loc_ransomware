#pragma once
#include <string>
#include <filesystem>
#include <windows.h>
#include "system_utils/WinAPIWrapper.h"
#include "evasion/ProcessHollowing.h"

class DllInjection {
	ProcessHollowing pHollowing;
public:
	DllInjection() = default;
	~DllInjection() = default;

	bool Inject(const std::filesystem::path& targetProcess, const std::filesystem::path& dllPath);
};

