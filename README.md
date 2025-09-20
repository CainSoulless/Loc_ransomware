# 🛠️ Loc Ransomware

**Loc** es un proyecto Ransomware de investigación orientado al estudio y práctica de técnicas de *code injection*, *remote thread execution*, *memory manipulation*, y evasión de análisis. Está escrito en C++, con algo de MASM (Microsoft Macro Assembler) y se estructura modularmente para separar cada fase de ejecución.

Este repositorio fue creado con fines de **researching** en seguridad ofensiva, específicamente en el análisis de comportamiento, evasión y técnicas post-explotación.

---

## 🚨 Características principales

- Inyección por **Remote Thread DLL Injection**
- Inyección directa de **shellcode en memoria**
- **Cifrado de archivos** usando XOR y cambio de extensión
- Técnicas de evasión de análisis y sandboxing
- **Persistencia** en el sistema vía Registry Keys
- Modularidad: cada técnica implementada como clase reutilizable

---

## 🔸 Evasión / Antianálisis y Persistencia

- **Dynamic API Resolution + Caesar Cipher Obfuscation**
  - Los nombres de funciones (`LoadLibraryA`, `GetProcAddress`, etc.) y DLLs (`kernel32.dll`, `ntdll.dll`) están cifrados mediante **Caesar cipher**.
  - Se desencriptan en tiempo de ejecución, dificultando el análisis estático y evitando detección por firmas simples.

- **Detección de máquinas virtuales / sandboxes**
  - Búsqueda de indicadores de entornos virtualizados: strings como `VBox`, `VMware`, `QEMU`, entre otros.
  - Evaluación de recursos del sistema (número de núcleos, memoria, etc.) para identificar entornos artificialmente limitados.

- **Detección de depuradores (anti-debug)**
  - Uso de funciones como `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`.
  - Inspección del campo `BeingDebugged` del `PEB`.
  - Técnicas pasivas como errores controlados para observar reacciones anómalas del entorno.

- **Manipulación del flujo de ejecución**
  - El ejecutable puede autocrashearse o desviar su comportamiento si se detecta un entorno de análisis dinámico o sandbox.
  - Esto dificulta la ejecución completa en entornos automatizados.

- **Persistencia en el sistema**
  - Se crean claves de registro (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) para persistencia tras reinicio del sistema.
  - El ejecutable se ejecuta nuevamente al iniciar sesión.

---

## 🧩 Posibles técnicas futuras

- **Timing-based sandbox detection**
- **Cash-as-Demand**
- **Comunicación a C2**
- **API unhooking desde ntdll.dll limpia** (Mi técnica favorita️❤️)

---

## ⚠️ Disclaimer

Este repositorio es únicamente con fines de **investigación profesional** en ciberseguridad. El uso indebido de este código fuera de entornos controlados y éticos **está completamente prohibido**.