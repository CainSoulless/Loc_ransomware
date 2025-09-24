#pragma once

#include "pch.h"

enum class LogLevel {
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	NONE
};

class Logger {
public:
	static void setLevel(LogLevel level);
	static LogLevel getLevel();

	static void debug(const std::wstring& msg);
	static void info(const std::wstring& msg);
	static void warning(const std::wstring& msg);
	static void error(const std::wstring& msg);

private:
	static LogLevel currentLevel;
};

