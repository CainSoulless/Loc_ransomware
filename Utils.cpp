#pragma once

#include "Utils.h"

Utils::Utils() {};

void Utils::changeWallpaper()
{
    const wchar_t* wallpaper = L"C:\\Users\\rodri\\Downloads\\wallpaper.png";
    //const wchar_t* wallpaper = L"C:\\Users\\rodri\\Downloads\\wallpaper2.png";

    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void*)wallpaper, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}