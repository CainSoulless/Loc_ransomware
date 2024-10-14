# Loc Ransomware 🛡️

**Loc Ransomware** es un proyecto educativo que implementa técnicas avanzadas de evasión, incluyendo **Process Hollowing** para inyectar código malicioso en procesos legítimos del sistema. Este proyecto está diseñado para ilustrar cómo operan algunos ransomware en el mundo real, permitiendo la investigación y la mejora de las capacidades de detección de malware.

## ⚠️ Disclaimer
Este proyecto es únicamente con fines educativos y de investigación. El uso indebido de este código está prohibido y podría resultar en consecuencias legales. No se recomienda utilizar este código en sistemas de producción o sin autorización.

## 🚀 Características
- **Process Hollowing**: Inyecta un shellcode en un proceso legítimo (`svchost.exe`, `notepad.exe`, etc.) para ejecutarlo bajo la apariencia de un proceso confiable.
- **Shellcode Injection**: Utiliza técnicas avanzadas para escribir y ejecutar código arbitrario en un proceso suspendido.
- **Técnicas de Evasión**: Implementación de técnicas básicas de evasión, como la detección de máquinas virtuales y sandboxes.

## 📂 Estructura del Proyecto

```bash
Loc_ransomware/
│
├── src/
│   ├── Loc.cpp                 # Punto de entrada principal del proyecto
│   ├── Evasion.cpp             # Implementación de técnicas de evasión
│   ├── ProcessHollowing.cpp    # Lógica de Process Hollowing
│   ├── Injection.cpp           # Manejador del shellcode
│   └── ...
│
├── include/
│   ├── Evasion.h               # Definiciones de la clase Evasion
│   ├── ProcessHollowing.h      # Definiciones de la clase ProcessHollowing
│   └── Injection.h             # Definiciones para la inyección de shellcode
│
└── README.md                   # Descripción del proyecto (este archivo)
```
## 🛠️ Instalación y Uso

### Requisitos Previos

*   **Sistema Operativo**: Windows (Requiere permisos de administrador)
*   **Compilador**: Microsoft Visual Studio o cualquier entorno con soporte para C++
*   **Herramientas de Depuración**: [Process Hacker](https://processhacker.sourceforge.io/), [ProcMon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) para inspeccionar el proceso y la memoria.

### Instrucciones

1.  **Clona el repositorio**:
    
    ```bash
    git clone https://github.com/CainSoulless/Loc_ransomware.git
    ```
    
2.  **Compila el proyecto** en tu entorno preferido (Visual Studio recomendado).

3.  **Ejecución**:
   Ejecuta el binario generado (`Loc.exe`). Por defecto, el código por defecto ejecuta `test.cpp`, por lo que se requiere reemplazar el valor del macro TEST_MODE a 0 para salir del modo de pruebas.

4.  **Monitoreo**:
   Utiliza herramientas como **Process Hacker** para verificar la inyección de código en el proceso objetivo.
