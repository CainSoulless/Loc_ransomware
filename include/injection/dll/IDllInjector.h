#pragma once
#include <filesystem>
#include <system_error>

class ProcessCreationInfo;

class IDllInjector {
public:
	virtual ~IDllInjector() = default;

	virtual bool injectInto(
		ProcessCreationInfo& pci,
		const std::filesystem::path& dllPath,
		std::error_code& ec) noexcept = 0;
};
