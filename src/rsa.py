"""
Generacion de pares de claves RSA, cifrado, descifrado y gestion de claves.

Implementacion pura en Python sin librerias criptograficas externas.
Utiliza modinv, modexp y gcd de mathcore y generate_prime de primes.
"""

import json
import sys
from pathlib import Path

# Soporte para ejecucion tanto como modulo (python -m src.rsa)
# como ejecucion directa como script (python src/rsa.py).
try:
    from .mathcore import gcd, modexp, modinv
    from .primes import generate_prime
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.mathcore import gcd, modexp, modinv
    from src.primes import generate_prime


# Exponente publico estandar de Fermat F4 = 2^16 + 1
E_DEFAULT: int = 65537


def bytes_to_int(b: bytes) -> int:
    """
    Convierte una secuencia de bytes en un entero grande utilizando orden big-endian.

    :param b: Secuencia de bytes.
    :return: Representacion entera no negativa.
    :raises TypeError: Si b no es de tipo bytes o bytearray.
    """
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("La entrada debe ser de tipo bytes o bytearray.")
    return int.from_bytes(b, "big")


def int_to_bytes(x: int, length: int | None = None) -> bytes:
    """
    Convierte un entero no negativo en una secuencia de bytes en orden big-endian.

    :param x: Entero no negativo a convertir.
    :param length: Longitud fija en bytes. Si es None, calcula la longitud minima
                   necesaria ((x.bit_length() + 7) // 8), devolviendo b"" si x == 0.
    :return: Representacion en bytes.
    :raises ValueError: Si x es negativo o no cabe en la longitud especificada.
    :raises TypeError: Si x o length no son enteros validos.
    """
    if not isinstance(x, int) or isinstance(x, bool):
        raise TypeError("El valor a convertir debe ser un entero.")
    if x < 0:
        raise ValueError("El entero no puede ser negativo.")
    if length is not None:
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("La longitud debe ser un entero.")
        return x.to_bytes(length, "big")
    longitud = (x.bit_length() + 7) // 8
    return x.to_bytes(longitud, "big")


def generate_keypair(bits: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Genera un par de claves RSA (publica y privada) con un modulo de la longitud dada.

    :param bits: Longitud total en bits del modulo n (entero par >= 512).
    :return: Tupla ((n, e), (n, d)) correspondiente a (clave_publica, clave_privada).
    :raises ValueError: Si bits no es entero, es menor que 512, o no es un numero par.
    """
    # 1. Validar parametro bits
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise ValueError("La longitud en bits debe ser un numero entero.")
    if bits < 512:
        raise ValueError("La longitud en bits debe ser al menos 512.")
    if bits % 2 != 0:
        raise ValueError("La longitud en bits debe ser un numero par.")

    half_bits = bits // 2
    e = E_DEFAULT

    # 2. Bucle de generacion hasta obtener primos validos que formen n de longitud exacta
    while True:
        # Generar primer primo p
        p = generate_prime(half_bits)

        # Si e divide a (p - 1), no sera coprimo con phi; regenerar p
        if gcd(e, p - 1) != 1:
            continue

        # Generar segundo primo q distinto de p y coprimo con e
        encontrado = False
        for _ in range(10):
            q = generate_prime(half_bits)
            if q == p:
                continue

            if gcd(e, q - 1) != 1:
                continue

            # Modulo RSA: n = p * q
            n = p * q

            # Asegurar que n tenga exactamente los bits solicitados
            if n.bit_length() != bits:
                continue

            # Funcion totiente de Euler: phi(n) = (p - 1) * (q - 1)
            phi = (p - 1) * (q - 1)

            # Verificar coprimalidad gcd(e, phi) == 1
            if gcd(e, phi) != 1:
                continue

            # Exponente privado d tal que (e * d) = 1 (mod phi)
            d = modinv(e, phi)
            encontrado = True
            break

        if encontrado:
            break

    # Clave publica: (n, e)
    public_key = (n, e)
    # Clave privada: (n, d)
    private_key = (n, d)

    return (public_key, private_key)


def encrypt(msg: bytes, public: tuple[int, int]) -> bytes:
    """
    Cifra un mensaje utilizando la clave publica RSA (n, e).

    Convierte el mensaje a entero m (big-endian), valida que 0 <= m < n y que su
    longitud no exceda la capacidad del modulo, y calcula c = modexp(m, e, n).
    Devuelve el criptograma con longitud fija = (n.bit_length() + 7) // 8 bytes.

    :param msg: Mensaje en bytes a cifrar.
    :param public: Tupla (n, e) con el modulo y exponente publico.
    :return: Criptograma en bytes con longitud fija.
    :raises TypeError: Si msg no es bytes o la clave publica no es tupla de enteros.
    :raises ValueError: Si el mensaje es demasiado largo para el modulo o clave invalida.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("El mensaje debe ser de tipo bytes o bytearray.")
    if not (isinstance(public, tuple) and len(public) == 2):
        raise TypeError("La clave publica debe ser una tupla (n, e).")

    n, e = public
    if not (isinstance(n, int) and isinstance(e, int) and not isinstance(n, bool) and not isinstance(e, bool)):
        raise TypeError("Los componentes de la clave publica deben ser enteros.")
    if n <= 0 or e <= 0:
        raise ValueError("Los componentes de la clave publica deben ser enteros positivos.")

    max_bytes = n.bit_length() // 8
    m = bytes_to_int(msg)

    # Validacion: m debe ser estrictamente menor que n y no exceder la longitud en bytes permitida
    if len(msg) >= max_bytes or m >= n:
        raise ValueError("mensaje demasiado largo para el modulo")

    # Exponenciacion modular: c = m^e (mod n)
    c = modexp(m, e, n)

    # Longitud fija en bytes del criptograma
    ct_len = (n.bit_length() + 7) // 8
    return int_to_bytes(c, length=ct_len)


def decrypt(ct: bytes, private: tuple[int, int]) -> bytes:
    """
    Descifra un criptograma utilizando la clave privada RSA (n, d).

    Convierte el criptograma a entero c, calcula m = modexp(c, d, n), y devuelve
    el mensaje original en bytes sin padding adicional.

    :param ct: Criptograma en bytes.
    :param private: Tupla (n, d) con el modulo y exponente privado.
    :return: Mensaje original en bytes.
    :raises TypeError: Si ct no es bytes o la clave privada no es tupla de enteros.
    :raises ValueError: Si la clave privada contiene valores invalidos o c >= n.
    """
    if not isinstance(ct, (bytes, bytearray)):
        raise TypeError("El criptograma debe ser de tipo bytes o bytearray.")
    if not (isinstance(private, tuple) and len(private) == 2):
        raise TypeError("La clave privada debe ser una tupla (n, d).")

    n, d = private
    if not (isinstance(n, int) and isinstance(d, int) and not isinstance(n, bool) and not isinstance(d, bool)):
        raise TypeError("Los componentes de la clave privada deben ser enteros.")
    if n <= 0 or d <= 0:
        raise ValueError("Los componentes de la clave privada deben ser enteros positivos.")

    c = bytes_to_int(ct)
    if c >= n:
        raise ValueError("El criptograma es invalido para el modulo.")

    # Exponenciacion modular: m = c^d (mod n)
    m = modexp(c, d, n)

    # Convertir entero m a bytes sin padding adicional
    return int_to_bytes(m)


def save_public_key(public: tuple[int, int], path: str | Path) -> None:
    """
    Guarda una clave publica RSA (n, e) en un archivo con formato JSON.

    Serializa los enteros n y e como cadenas hexadecimales con prefijo '0x'.
    Se emplea representacion hexadecimal porque los modulos RSA superan el
    rango de enteros seguros (Number.MAX_SAFE_INTEGER = 2^53 - 1) de muchos parsers JSON.

    :param public: Tupla (n, e) con la clave publica.
    :param path: Ruta del archivo donde guardar la clave (str o Path).
    :raises TypeError: Si los parametros no tienen los tipos esperados.
    :raises ValueError: Si los componentes de la clave no son positivos.
    """
    if not (isinstance(public, tuple) and len(public) == 2):
        raise TypeError("La clave publica debe ser una tupla (n, e).")
    n, e = public
    if not (isinstance(n, int) and isinstance(e, int) and not isinstance(n, bool) and not isinstance(e, bool)):
        raise TypeError("Los componentes n y e deben ser enteros.")
    if n <= 0 or e <= 0:
        raise ValueError("Los componentes de la clave publica deben ser enteros positivos.")

    data = {
        "n": hex(n),
        "e": hex(e)
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_public_key(path: str | Path) -> tuple[int, int]:
    """
    Carga una clave publica RSA (n, e) desde un archivo JSON.

    Espera un objeto JSON con campos 'n' y 'e' codificados en hexadecimal con prefijo '0x'.
    Si el archivo no existe, lanza FileNotFoundError.
    Si el JSON esta corrupto, faltan campos o los valores son invalidos, lanza ValueError.

    :param path: Ruta del archivo JSON a cargar (str o Path).
    :return: Tupla (n, e) con la clave publica.
    :raises FileNotFoundError: Si el archivo no existe.
    :raises ValueError: Si el archivo esta corrupto o el formato es invalido.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Archivo de clave no encontrado: {path}")

    try:
        with open(path_obj, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(f"JSON corrupto o invalido: {err}") from err
    except Exception as err:
        raise ValueError(f"Error al leer archivo de clave: {err}") from err

    if not isinstance(data, dict):
        raise ValueError("El contenido del JSON debe ser un diccionario.")

    if "n" not in data or "e" not in data:
        raise ValueError("El JSON de clave publica debe contener los campos 'n' y 'e'.")

    try:
        n_str = data["n"]
        e_str = data["e"]
        if not (isinstance(n_str, str) and isinstance(e_str, str)):
            raise ValueError("Los valores de 'n' y 'e' deben ser cadenas de texto.")
        n = int(n_str, 16)
        e = int(e_str, 16)
    except (ValueError, TypeError) as err:
        raise ValueError(f"Formato hexadecimal invalido en clave publica: {err}") from err

    if n <= 0 or e <= 0:
        raise ValueError("Los componentes de la clave publica deben ser enteros positivos.")

    return (n, e)


def save_private_key(private: tuple[int, int], path: str | Path) -> None:
    """
    Guarda una clave privada RSA (n, d) en un archivo con formato JSON.

    ADVERTENCIA DE SEGURIDAD:
    El archivo resultante contiene el exponente privado en texto plano (sin cifrar).
    El almacenamiento protegido mediante derivacion de contrasena y cifrado simetrico
    esta fuera del alcance de este modulo y sera gestionado por la interfaz de usuario (GUI).
    Asegurese de almacenar este archivo en un entorno con control de acceso estricto.

    Serializa los enteros n y d como cadenas hexadecimales con prefijo '0x'
    para prevenir perdidas de precision en parsers JSON genericos.

    :param private: Tupla (n, d) con la clave privada.
    :param path: Ruta del archivo donde guardar la clave (str o Path).
    :raises TypeError: Si los parametros no tienen los tipos esperados.
    :raises ValueError: Si los componentes de la clave no son positivos.
    """
    if not (isinstance(private, tuple) and len(private) == 2):
        raise TypeError("La clave privada debe ser una tupla (n, d).")
    n, d = private
    if not (isinstance(n, int) and isinstance(d, int) and not isinstance(n, bool) and not isinstance(d, bool)):
        raise TypeError("Los componentes n y d deben ser enteros.")
    if n <= 0 or d <= 0:
        raise ValueError("Los componentes de la clave privada deben ser enteros positivos.")

    data = {
        "n": hex(n),
        "d": hex(d)
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_private_key(path: str | Path) -> tuple[int, int]:
    """
    Carga una clave privada RSA (n, d) desde un archivo JSON.

    Espera un objeto JSON con campos 'n' y 'd' codificados en hexadecimal con prefijo '0x'.
    Si el archivo no existe, lanza FileNotFoundError.
    Si el JSON esta corrupto, faltan campos o los valores son invalidos, lanza ValueError.

    :param path: Ruta del archivo JSON a cargar (str o Path).
    :return: Tupla (n, d) con la clave privada.
    :raises FileNotFoundError: Si el archivo no existe.
    :raises ValueError: Si el archivo esta corrupto o el formato es invalido.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Archivo de clave no encontrado: {path}")

    try:
        with open(path_obj, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(f"JSON corrupto o invalido: {err}") from err
    except Exception as err:
        raise ValueError(f"Error al leer archivo de clave: {err}") from err

    if not isinstance(data, dict):
        raise ValueError("El contenido del JSON debe ser un diccionario.")

    if "n" not in data or "d" not in data:
        raise ValueError("El JSON de clave privada debe contener los campos 'n' y 'd'.")

    try:
        n_str = data["n"]
        d_str = data["d"]
        if not (isinstance(n_str, str) and isinstance(d_str, str)):
            raise ValueError("Los valores de 'n' y 'd' deben ser cadenas de texto.")
        n = int(n_str, 16)
        d = int(d_str, 16)
    except (ValueError, TypeError) as err:
        raise ValueError(f"Formato hexadecimal invalido en clave privada: {err}") from err

    if n <= 0 or d <= 0:
        raise ValueError("Los componentes de la clave privada deben ser enteros positivos.")

    return (n, d)


if __name__ == "__main__":
    import time

    print("=== Demo Generacion de Claves RSA ===")
    t_inicio = time.perf_counter()
    clave_pub, clave_priv = generate_keypair(1024)
    t_fin = time.perf_counter()

    n_pub, e_val = clave_pub
    n_priv, d_val = clave_priv

    print(f"Tiempo de generacion (1024 bits): {t_fin - t_inicio:.4f} segundos")
    print(f"Modulo n: longitud = {n_pub.bit_length()} bits")
    print(f"Exponente publico e: valor = {e_val}, longitud = {e_val.bit_length()} bits")
    print(f"Exponente privado d: longitud = {d_val.bit_length()} bits")
    print("Generacion de claves completada con exito.")

    print("\n=== Demo Cifrado y Descifrado RSA (512 bits) ===")
    pub512, priv512 = generate_keypair(512)
    mensaje_original = b"Hola RSA"
    criptograma = encrypt(mensaje_original, pub512)
    mensaje_recuperado = decrypt(criptograma, priv512)

    print(f"Mensaje original: {mensaje_original.decode('utf-8')}")
    print(f"Criptograma (longitud {len(criptograma)} bytes): {criptograma.hex()[:32]}...")
    print(f"Mensaje recuperado: {mensaje_recuperado.decode('utf-8')}")
    print(f"Round-trip exitoso: {mensaje_recuperado == mensaje_original}")
