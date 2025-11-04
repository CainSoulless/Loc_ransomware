#include "Logger.h"

#ifdef _WIN32
#include <Windows.h> // WideCharToMultiByte
#else
#include <locale>
#include <codecvt> // fallback para otras plataformas
#endif

#include <string>
#include <iostream>

// inicialización del nivel por defecto
LogLevel Logger::currentLevel =
#ifdef _DEBUG
LogLevel::DEBUG;
#else
LogLevel::ERR;
#endif

// Helper: wstring -> UTF-8 std::string (Windows: WideCharToMultiByte)
std::string Logger::toUtf8(const std::wstring& wstr)
{
#ifdef _WIN32
    if (wstr.empty()) return std::string();

    // pide tamaño incluyendo el terminador nulo
    int size_needed = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        -1,    // incluye el '\0'
        nullptr,
        0,
        nullptr,
        nullptr);

    if (size_needed <= 0) {
        return std::string();
    }

    // size_needed incluye espacio para el '\0', así que reservamos size_needed - 1
    std::string out(static_cast<size_t>(size_needed) - 1, '\0');

    int res = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        -1,
        &out[0],
        size_needed,
        nullptr,
        nullptr);

    if (res <= 0) {
        return std::string();
    }

    return out;
#else
    // Fallback portable (puede advertir en C++17+)
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(wstr);
#endif
}

void Logger::setLevel(LogLevel level)
{
    currentLevel = level;
}

LogLevel Logger::getLevel()
{
    return currentLevel;
}

// --- std::string ---

void Logger::debug(const std::string& msg)
{
    if (currentLevel <= LogLevel::DEBUG) {
        std::cout << "[DEBUG] " << msg << std::endl;
    }
}

void Logger::info(const std::string& msg)
{
    if (currentLevel <= LogLevel::INFO) {
        std::cout << "[INFO] " << msg << std::endl;
    }
}

void Logger::warning(const std::string& msg)
{
    if (currentLevel <= LogLevel::WARNING) {
        std::cout << "[WARNING] " << msg << std::endl;
    }
}

void Logger::error(const std::string& msg)
{
    if (currentLevel <= LogLevel::ERR) {
        std::cout << "[ERROR] " << msg << std::endl;
    }
}

// --- std::wstring (sobrecargas) ---

void Logger::debug(const std::wstring& msg)
{
    debug(toUtf8(msg));
}

void Logger::info(const std::wstring& msg)
{
    info(toUtf8(msg));
}

void Logger::warning(const std::wstring& msg)
{
    warning(toUtf8(msg));
}

void Logger::error(const std::wstring& msg)
{
    error(toUtf8(msg));
}
