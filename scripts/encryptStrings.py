def encrypt_caesar(mensaje, key):
    # Convertimos el mensaje de texto en una lista de enteros (bytes)
    data = [ord(char) for char in mensaje]

    # Recorremos cada byte y aplicamos el cifrado
    for i in range(len(data)):
        data[i] = (data[i] + key) % 256  # Aseguramos que el byte esté en el rango [0, 255]

    return data  # Devuelve la lista de bytes cifrados


def imprimir_bytes_en_hexadecimal(bytes_cifrados):
    # Convertimos cada byte en su representación hexadecimal
    return ' '.join(f"{byte:02x}" for byte in bytes_cifrados)


def decrypt_caesar(data_cifrada, key):
    # Recorremos cada byte y aplicamos el descifrado
    for i in range(len(data_cifrada)):
        data_cifrada[i] = (data_cifrada[i] + (256 - key)) % 256  # Inversión de la operación de cifrado

    # Convertimos la lista de enteros a una cadena de caracteres
    decrypted_str = ''.join(chr(byte) for byte in data_cifrada)

    return decrypted_str


def print_var_version(nombre_variable, mensaje_cifrado):
    # Convertimos cada byte en un string con el formato necesario
    elementos = ', '.join(f"0x{char:02x}" for char in mensaje_cifrado)
    # Imprimimos el vector con los elementos
    print(f"std::vector<unsigned char> {nombre_variable} = {{ {elementos} }};")


# Ejemplo de uso
mensaje = "ntdll.dll"
desplazamiento = 0xDE  # Clave de desplazamiento en hexadecimal

# Cifrar el mensaje
mensaje_cifrado = encrypt_caesar(mensaje, desplazamiento)
print(f"Mensaje cifrado en bytes: {mensaje_cifrado}")
print(f"Mensaje cifrado en hexadecimal: {imprimir_bytes_en_hexadecimal(mensaje_cifrado)}")
print_var_version(mensaje, mensaje_cifrado)

# Descifrar el mensaje
mensaje_descifrado = decrypt_caesar(mensaje_cifrado[:], desplazamiento)  # Usamos una copia para descifrar
print(f"Mensaje descifrado: {mensaje_descifrado}")
