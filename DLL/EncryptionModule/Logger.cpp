#include "pch.h"
#include "Logger.h"

LogLevel Logger::currentLevel =
#ifdef _DEBUG
	LogLevel::DEBUG;
#else
	LogLevel::ERROR;
#endif

void Logger::setLevel(LogLevel level)
{
	currentLevel = level;
}

LogLevel Logger::getLevel()
{
	return currentLevel;
}

void Logger::debug(const std::wstring& msg)
{
	if (currentLevel <= LogLevel::DEBUG) {
		std::wcout << L"[DEBUG]" << msg << std::endl;
	}
}

void Logger::info(const std::wstring& msg)
{
	if (currentLevel <= LogLevel::INFO) {
		std::wcout << L"[INFO]" << msg << std::endl;
	}
}

void Logger::warning(const std::wstring& msg)
{
	if (currentLevel <= LogLevel::WARNING) {
		std::wcout << L"[WARNING]" << msg << std::endl;
	}
}

void Logger::error(const std::wstring& msg)
{
	if (currentLevel <= LogLevel::ERROR) {
		std::wcout << L"[ERROR]" << msg << std::endl;
	}
}
