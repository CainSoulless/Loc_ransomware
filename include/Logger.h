#pragma once

#include <iostream>
#include <string>

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERR,
    NONE
};

class Logger {
public:
    static void setLevel(LogLevel level);
    static LogLevel getLevel();

    // std::string
    static void debug(const std::string& msg);
    static void info(const std::string& msg);
    static void warning(const std::string& msg);
    static void error(const std::string& msg);

    // std::wstring (sobrecargas nuevas)
    static void debug(const std::wstring& msg);
    static void info(const std::wstring& msg);
    static void warning(const std::wstring& msg);
    static void error(const std::wstring& msg);

private:
    static LogLevel currentLevel;

    // helper privado para convertir wstring -> UTF-8 string
    static std::string toUtf8(const std::wstring& wstr);
};
