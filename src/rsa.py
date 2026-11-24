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
    from .oaep import DECRYPTION_ERROR, oaep_decode, oaep_encode
    from .pss import emsa_pss_encode, emsa_pss_verify
    from .sha256 import sha256
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.mathcore import gcd, modexp, modinv
    from src.primes import generate_prime
    from src.oaep import DECRYPTION_ERROR, oaep_decode, oaep_encode
    from src.pss import emsa_pss_encode, emsa_pss_verify
    from src.sha256 import sha256


# Exponente publico estandar de Fermat F4 = 2^16 + 1
E_DEFAULT: int = 65537

# Tamano minimo de modulo aceptado por defecto al usar una clave publica.
MIN_PUBLIC_BITS: int = 1024


def _es_entero(x) -> bool:
    """True si x es int y no bool (bool es subclase de int en Python)."""
    return isinstance(x, int) and not isinstance(x, bool)


def validate_public_key(public: tuple[int, int], allow_weak: bool = False) -> tuple[int, int]:
    """
    Valida una clave publica RSA (n, e) antes de usarla (principio Zero-Trust).

    Reglas:
    - n entero positivo e impar (producto de dos primos impares).
    - e impar y 3 <= e < n. Esto rechaza e = 1, con el que s^e = s y cualquiera
      podria "firmar" sin la clave privada.
    - n con al menos MIN_PUBLIC_BITS bits, salvo allow_weak=True (solo tests y
      demostraciones de ataque).

    :return: (n, e) validados.
    :raises TypeError: si no es una tupla de dos enteros.
    :raises ValueError: si la clave no cumple las reglas.
    """
    if not (isinstance(public, tuple) and len(public) == 2):
        raise TypeError("La clave publica debe ser una tupla (n, e).")
    n, e = public
    if not (_es_entero(n) and _es_entero(e)):
        raise TypeError("Los componentes de la clave publica deben ser enteros.")
    if n <= 0 or n % 2 == 0:
        raise ValueError("Clave publica invalida: n debe ser un entero positivo impar.")
    if e % 2 == 0 or e < 3 or e >= n:
        raise ValueError("Clave publica invalida: e debe ser impar y cumplir 3 <= e < n.")
    if not allow_weak and n.bit_length() < MIN_PUBLIC_BITS:
        raise ValueError(
            f"Clave publica debil: n tiene {n.bit_length()} bits y se requieren al menos "
            f"{MIN_PUBLIC_BITS}. (allow_weak=True solo para pruebas o demostraciones)."
        )
    return n, e


def _validate_private_key(private: tuple[int, int]) -> tuple[int, int]:
    """
    Comprobaciones basicas de una clave privada (n, d): tupla de dos enteros
    positivos. Centraliza la validacion que antes estaba copiada en cada funcion.

    :raises TypeError: si no es una tupla de dos enteros.
    :raises ValueError: si algun componente no es positivo.
    """
    if not (isinstance(private, tuple) and len(private) == 2):
        raise TypeError("La clave privada debe ser una tupla (n, d).")
    n, d = private
    if not (_es_entero(n) and _es_entero(d)):
        raise TypeError("Los componentes de la clave privada deben ser enteros.")
    if n <= 0 or d <= 0:
        raise ValueError("Los componentes de la clave privada deben ser enteros positivos.")
    return n, d


def public_key_fingerprint(public: tuple[int, int]) -> str:
    """
    Huella de una clave publica: SHA-256 (implementacion propia) de n || e.

    n se codifica en big-endian con longitud fija k = ceil(bits(n) / 8) y e en
    big-endian con la longitud minima. Sirve para que dos personas comprueben
    por un canal aparte que tienen la misma clave publica.

    :return: huella en hexadecimal (64 caracteres).
    """
    n, e = validate_public_key(public, allow_weak=True)
    k = (n.bit_length() + 7) // 8
    return sha256(n.to_bytes(k, "big") + e.to_bytes((e.bit_length() + 7) // 8, "big")).hex()


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

            # FIPS 186-4 (B.3.1): |p - q| > 2^(bits/2 - 100). Si p y q fueran
            # demasiado cercanos, la factorizacion de Fermat romperia n.
            if abs(p - q) <= (1 << (half_bits - 100)):
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


def encrypt(msg: bytes, public: tuple[int, int], allow_weak: bool = False) -> bytes:
    """
    RSA "textbook" (sin relleno): SOLO DEMOSTRACION, INSEGURO.

    Es determinista (mismo mensaje -> mismo criptograma), maleable
    (E(a)*E(b) = E(a*b) mod n) y, con e pequeno y mensajes cortos, se invierte
    con una raiz entera. Se conserva unicamente para las demostraciones de
    ataque. Para cifrar de verdad use encrypt_oaep.

    Convierte el mensaje a entero m (big-endian), valida que 0 <= m < n y que su
    longitud no exceda la capacidad del modulo, y calcula c = modexp(m, e, n).
    Devuelve el criptograma con longitud fija = (n.bit_length() + 7) // 8 bytes.

    :param msg: Mensaje en bytes a cifrar.
    :param public: Tupla (n, e) con el modulo y exponente publico.
    :param allow_weak: Acepta modulos de menos de MIN_PUBLIC_BITS (solo demos/tests).
    :return: Criptograma en bytes con longitud fija.
    :raises TypeError: Si msg no es bytes o la clave publica no es tupla de enteros.
    :raises ValueError: Si el mensaje es demasiado largo para el modulo o clave invalida.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("El mensaje debe ser de tipo bytes o bytearray.")
    n, e = validate_public_key(public, allow_weak=allow_weak)

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


def decrypt(ct: bytes, private: tuple[int, int], length: int | None = None) -> bytes:
    """
    RSA "textbook" (sin relleno): SOLO DEMOSTRACION, INSEGURO. Ver encrypt().

    Convierte el criptograma a entero c y calcula m = modexp(c, d, n).

    Sin relleno, el entero m no guarda cuantos bytes 0x00 tenia el mensaje al
    principio. Por eso:
    - length=None: devuelve la representacion minima de m (se pierden los
      ceros iniciales; b"\\x00\\x00ABC" vuelve como b"ABC").
    - length=L: devuelve exactamente L bytes (I2OSP de RFC 8017), recuperando
      los ceros iniciales. Use L = len(mensaje original) o L = k (bytes de n).

    :param ct: Criptograma en bytes.
    :param private: Tupla (n, d) con el modulo y exponente privado.
    :param length: Longitud de salida en bytes (opcional).
    :return: Mensaje original en bytes.
    :raises TypeError: Si ct no es bytes o la clave privada no es tupla de enteros.
    :raises ValueError: Si la clave privada contiene valores invalidos o c >= n.
    """
    if not isinstance(ct, (bytes, bytearray)):
        raise TypeError("El criptograma debe ser de tipo bytes o bytearray.")
    n, d = _validate_private_key(private)

    c = bytes_to_int(ct)
    if c >= n:
        raise ValueError("El criptograma es invalido para el modulo.")

    # Exponenciacion modular: m = c^d (mod n)
    m = modexp(c, d, n)

    # Convertir entero m a bytes: longitud minima o fija si se indico
    if length is None:
        return int_to_bytes(m)
    return int_to_bytes(m, length=length)


def encrypt_oaep(msg: bytes, public: tuple[int, int], label: bytes = b"",
                 allow_weak: bool = False) -> bytes:
    """
    Cifra un mensaje utilizando relleno OAEP (SHA-256) y clave publica RSA (n, e).

    Aplica oaep_encode(msg, k, label) donde k = (n.bit_length() + 7) // 8,
    convierte el bloque codificado EM a entero m, y calcula c = modexp(m, e, n).
    Devuelve el criptograma de longitud fija k bytes.

    :param msg: Mensaje en bytes a cifrar.
    :param public: Tupla (n, e) con el modulo y exponente publico.
    :param label: Etiqueta opcional asociada.
    :param allow_weak: Acepta modulos de menos de MIN_PUBLIC_BITS (solo demos/tests).
    :return: Criptograma en bytes de longitud k.
    :raises TypeError: Si los parametros no tienen los tipos esperados.
    :raises ValueError: Si la clave es invalida, el modulo es insuficiente o el mensaje
                        excede la capacidad.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("El mensaje debe ser de tipo bytes o bytearray.")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("La etiqueta debe ser de tipo bytes o bytearray.")
    n, e = validate_public_key(public, allow_weak=allow_weak)

    k = (n.bit_length() + 7) // 8
    max_len = k - 2 * 32 - 2
    if max_len < 0:
        raise ValueError(
            f"Clave de {n.bit_length()} bits demasiado pequena para OAEP-SHA256: "
            f"se requieren al menos {8 * (2 * 32 + 1) + 1} bits (k >= 66 bytes)."
        )
    if len(msg) > max_len:
        raise ValueError(
            f"Mensaje demasiado largo para OAEP-SHA256: {len(msg)} > {max_len} bytes."
        )

    em = oaep_encode(msg, k, label)
    m = bytes_to_int(em)
    c = modexp(m, e, n)
    return int_to_bytes(c, length=k)


def decrypt_oaep(ct: bytes, private: tuple[int, int], label: bytes = b"") -> bytes:
    """
    Descifra un criptograma con relleno OAEP (SHA-256) y clave privada RSA (n, d).

    Verifica c < n, calcula m = modexp(c, d, n), convierte m a bloque EM de k bytes,
    y aplica oaep_decode(em, k, label).

    Todos los fallos (longitud, c >= n, relleno, etiqueta) lanzan el MISMO
    ValueError("decryption error"): distinguir la causa daria a un atacante un
    oraculo de relleno (ataque de Manger / Bleichenbacher).

    :param ct: Criptograma en bytes de longitud k.
    :param private: Tupla (n, d) con el modulo y exponente privado.
    :param label: Etiqueta opcional asociada.
    :return: Mensaje original en bytes.
    :raises TypeError: Si los parametros no tienen los tipos esperados.
    :raises ValueError: "decryption error" ante cualquier fallo de descifrado.
    """
    if not isinstance(ct, (bytes, bytearray)):
        raise TypeError("El criptograma debe ser de tipo bytes o bytearray.")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("La etiqueta debe ser de tipo bytes o bytearray.")
    n, d = _validate_private_key(private)

    k = (n.bit_length() + 7) // 8
    if len(ct) != k:
        raise ValueError(DECRYPTION_ERROR)

    c = bytes_to_int(ct)
    if c >= n:
        raise ValueError(DECRYPTION_ERROR)

    m = modexp(c, d, n)
    em = int_to_bytes(m, length=k)
    return oaep_decode(em, k, label)


def sign(msg: bytes, private: tuple[int, int], salt_len: int = 32) -> bytes:
    """
    Firma un mensaje utilizando el esquema RSA-PSS con SHA-256 (RFC 8017).

    Calcula mHash = SHA-256(msg) y delega en sign_hash.

    :param msg: Mensaje en bytes a firmar.
    :param private: Tupla (n, d) con la clave privada RSA.
    :param salt_len: Longitud del salt aleatorio en bytes (por defecto 32).
    :return: Firma digital en bytes de longitud k bytes.
    :raises TypeError: Si msg no es bytes o la clave privada no es tupla de enteros.
    :raises ValueError: Si la clave privada es invalida o el modulo es insuficiente.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("El mensaje debe ser de tipo bytes o bytearray.")
    return sign_hash(sha256(bytes(msg)), private, salt_len=salt_len)


def sign_hash(m_hash: bytes, private: tuple[int, int], salt_len: int = 32) -> bytes:
    """
    Firma RSA-PSS a partir del resumen SHA-256 ya calculado (32 bytes).

    Permite firmar archivos grandes resumidos por bloques con sha256_file.
    Aplica EMSA-PSS-SHA256 con em_bits = n.bit_length() - 1, convierte EM a
    entero m y calcula s = m^d (mod n). Devuelve k bytes.
    """
    if not isinstance(m_hash, (bytes, bytearray)) or len(m_hash) != 32:
        raise TypeError("m_hash debe ser un resumen SHA-256 de 32 bytes.")
    n, d = _validate_private_key(private)

    k = (n.bit_length() + 7) // 8
    em_bits = n.bit_length() - 1
    if (em_bits + 7) // 8 < 32 + salt_len + 2:
        raise ValueError(
            f"Clave de {n.bit_length()} bits demasiado pequena para PSS-SHA256 con salt de "
            f"{salt_len} bytes: se requieren al menos {8 * (32 + salt_len + 1) + 2} bits."
        )

    # Codificacion EMSA-PSS
    em = emsa_pss_encode(bytes(m_hash), em_bits, salt_len=salt_len)

    # Conversion a entero y operacion con clave privada s = m^d (mod n)
    m = bytes_to_int(em)
    s = modexp(m, d, n)

    # Devolver firma de longitud fija k bytes
    return int_to_bytes(s, length=k)


def verify(msg: bytes, sig: bytes, public: tuple[int, int], salt_len: int = 32,
           allow_weak: bool = False) -> bool:
    """
    Verifica una firma digital RSA-PSS con SHA-256 (RFC 8017).

    Convierte la firma sig a entero s, valida s < n y que su longitud sea k,
    recupera el mensaje codificado m = s^e (mod n), lo formatea a em_len bytes,
    y ejecuta la verificacion EMSA-PSS-SHA256 contra el hash del mensaje.

    NUNCA lanza excepciones por firma invalida: devuelve False. Si lanza
    ValueError cuando la CLAVE PUBLICA es invalida o debil (por ejemplo e = 1,
    con la que cualquiera fabricaria una firma "valida" sin la clave privada).

    :param msg: Mensaje original en bytes.
    :param sig: Firma en bytes a verificar.
    :param public: Tupla (n, e) con la clave publica RSA.
    :param salt_len: Longitud del salt esperado en bytes (por defecto 32).
    :param allow_weak: Acepta modulos de menos de MIN_PUBLIC_BITS (solo demos/tests).
    :return: True si la firma es valida, False en caso contrario.
    :raises TypeError: Si msg, sig, public o sus componentes no tienen tipos validos.
    :raises ValueError: Si la clave publica no supera validate_public_key.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("El mensaje debe ser de tipo bytes o bytearray.")
    return verify_hash(sha256(bytes(msg)), sig, public, salt_len=salt_len, allow_weak=allow_weak)


def verify_hash(m_hash: bytes, sig: bytes, public: tuple[int, int], salt_len: int = 32,
                allow_weak: bool = False) -> bool:
    """
    Verifica una firma RSA-PSS a partir del resumen SHA-256 ya calculado.

    Misma semantica que verify(): False ante firma invalida, ValueError ante
    clave publica invalida o debil.
    """
    if not isinstance(m_hash, (bytes, bytearray)) or len(m_hash) != 32:
        raise TypeError("m_hash debe ser un resumen SHA-256 de 32 bytes.")
    if not isinstance(sig, (bytes, bytearray)):
        raise TypeError("La firma debe ser de tipo bytes o bytearray.")
    if not isinstance(salt_len, int) or isinstance(salt_len, bool):
        raise TypeError("salt_len debe ser un entero.")
    n, e = validate_public_key(public, allow_weak=allow_weak)

    k = (n.bit_length() + 7) // 8
    # Validar longitud de la firma: debe ser exactamente k bytes
    if len(sig) != k:
        return False

    s = bytes_to_int(sig)
    # Firma s debe ser estrictamente menor que el modulo n
    if s >= n:
        return False

    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8

    # Modulo debe admitir la longitud requerida para PSS
    if em_len < 32 + salt_len + 2:
        return False

    # Operacion con clave publica m = s^e (mod n)
    m = modexp(s, e, n)

    # Convertir m a bloque EM de em_len bytes
    try:
        em = int_to_bytes(m, length=em_len)
    except (ValueError, OverflowError):
        return False

    # Verificacion EMSA-PSS contra el resumen del mensaje
    return emsa_pss_verify(bytes(m_hash), em, em_bits, salt_len=salt_len)


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
    # Al guardar se aceptan claves de demo (512 bits); al cargar se valida el tamano.
    n, e = validate_public_key(public, allow_weak=True)

    data = {
        "n": hex(n),
        "e": hex(e)
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_public_key(path: str | Path, allow_weak: bool = False) -> tuple[int, int]:
    """
    Carga una clave publica RSA (n, e) desde un archivo JSON.

    Espera un objeto JSON con campos 'n' y 'e' codificados en hexadecimal con prefijo '0x'.
    Si el archivo no existe, lanza FileNotFoundError.
    Si el JSON esta corrupto, faltan campos o los valores son invalidos, lanza ValueError.
    La clave cargada pasa por validate_public_key (no se confia en el archivo).

    :param path: Ruta del archivo JSON a cargar (str o Path).
    :param allow_weak: Acepta modulos de menos de MIN_PUBLIC_BITS (solo demos/tests).
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

    return validate_public_key((n, e), allow_weak=allow_weak)


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
    n, d = _validate_private_key(private)

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

    print("\n=== Demo RSA textbook (512 bits) - SOLO DEMOSTRACION, INSEGURO ===")
    pub512, priv512 = generate_keypair(512)
    mensaje_original = b"Hola RSA"
    criptograma = encrypt(mensaje_original, pub512, allow_weak=True)
    mensaje_recuperado = decrypt(criptograma, priv512)

    print(f"Mensaje original: {mensaje_original.decode('utf-8')}")
    print(f"Criptograma (longitud {len(criptograma)} bytes): {criptograma.hex()[:32]}...")
    print(f"Mensaje recuperado: {mensaje_recuperado.decode('utf-8')}")
    print(f"Round-trip exitoso: {mensaje_recuperado == mensaje_original}")

    print("\n=== Demo Cifrado y Descifrado RSA con Relleno OAEP ===")
    pub512_demo, priv512_demo = generate_keypair(512)
    # Comprobar comportamiento ante clave de 512 bits (k=64 < 66 bytes requeridos por OAEP-SHA256)
    try:
        encrypt_oaep(b"Hola OAEP", pub512_demo, allow_weak=True)
        error_capturado = False
    except ValueError:
        error_capturado = True
    print(f"Rechazo correcto de clave 512 bits por capacidad OAEP-SHA256: {error_capturado}")

    pub1024_demo, priv1024_demo = generate_keypair(1024)
    mensaje_oaep = b"Hola OAEP"
    ct_oaep = encrypt_oaep(mensaje_oaep, pub1024_demo)
    recuperado_oaep = decrypt_oaep(ct_oaep, priv1024_demo)

    print(f"Mensaje original OAEP: {mensaje_oaep.decode('utf-8')}")
    print(f"Criptograma OAEP (longitud {len(ct_oaep)} bytes): {ct_oaep.hex()[:32]}...")
    print(f"Mensaje recuperado OAEP: {recuperado_oaep.decode('utf-8')}")
    print(f"Round-trip OAEP exitoso: {recuperado_oaep == mensaje_oaep}")

    print("\n=== Demo Firma y Verificacion RSA-PSS (1024 bits) ===")
    pub1024_pss, priv1024_pss = generate_keypair(1024)
    msg_pss = b"Hola PSS"
    firma_pss = sign(msg_pss, priv1024_pss)
    valida_pss = verify(msg_pss, firma_pss, pub1024_pss)
    print(f"Mensaje PSS: {msg_pss.decode('utf-8')}")
    print(f"Firma PSS (longitud {len(firma_pss)} bytes): {firma_pss.hex()[:32]}...")
    print(f"Verificacion firma original: {valida_pss}")

    # Alterar 1 bit de la firma
    firma_alterada = bytes([firma_pss[0] ^ 0x01]) + firma_pss[1:]
    valida_alterada = verify(msg_pss, firma_alterada, pub1024_pss)
    print(f"Verificacion firma alterada (1 bit): {valida_alterada}")

    # Verificar mensaje distinto
    valida_distinto = verify(b"Mensaje distinto", firma_pss, pub1024_pss)
    print(f"Verificacion mensaje distinto: {valida_distinto}")
