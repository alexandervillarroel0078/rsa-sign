"""
Implementacion de relleno OAEP (Optimal Asymmetric Encryption Padding) con SHA-256.

Cumple con RFC 8017 (PKCS#1 v2.2). Utiliza la funcion hash SHA-256 propia (src.sha256)
y el generador criptografico seguro secrets del sistema.
"""

import secrets
import sys
from pathlib import Path

try:
    from .sha256 import sha256
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.sha256 import sha256


# Longitud en bytes de la salida de SHA-256 (256 bits = 32 bytes)
HLEN: int = 32

# Limite teorico maximo de longitud de mascara para MGF1 con SHA-256 (2^32 * 32 bytes)
MGF1_MAX_LEN: int = (1 << 32) * HLEN

# Mensaje unico para TODO fallo de descifrado (RFC 8017, seccion 7.1.2, nota):
# si el error dijera la causa (primer byte, lHash, separador...), un atacante
# podria usarlo como oraculo de relleno (ataque de Manger) y descifrar sin d.
DECRYPTION_ERROR: str = "decryption error"


def _ct_byte_eq(a: int, b: int) -> int:
    """
    Igualdad de dos bytes sin ramas: devuelve 1 si a == b y 0 si no.

    x = a ^ b esta en [0, 255]. Si x == 0, (x - 1) >> 8 = -1 y su bit bajo es 1;
    si x >= 1, (x - 1) >> 8 = 0.
    """
    return ((((a ^ b) - 1) >> 8) & 1)


def mgf1(seed: bytes, length: int) -> bytes:
    """
    Funcion de generacion de mascara MGF1 basada en SHA-256 (RFC 8017 Seccion B.2.1).

    :param seed: Semilla de entrada en bytes.
    :param length: Longitud deseada de la mascara de salida en bytes.
    :return: Mascara pseudoaleatoria de longitud solicitada.
    :raises TypeError: Si seed no es bytes o length no es un entero.
    :raises ValueError: Si length es negativo o supera la capacidad maxima.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed debe ser de tipo bytes o bytearray.")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length debe ser un entero.")
    if length < 0:
        raise ValueError("length no puede ser negativo.")
    if length > MGF1_MAX_LEN:
        raise ValueError("length excede el limite maximo para MGF1 con SHA-256.")

    if length == 0:
        return b""

    mascara = bytearray()
    contador = 0
    # Generar bloques de hash concatenando la semilla y el contador de 4 bytes big-endian
    while len(mascara) < length:
        c = contador.to_bytes(4, "big")
        mascara.extend(sha256(bytes(seed) + c))
        contador += 1

    return bytes(mascara[:length])


def oaep_encode(msg: bytes, k: int, label: bytes = b"") -> bytes:
    """
    Codifica un mensaje aplicando el esquema de relleno OAEP con SHA-256 (RFC 8017).

    :param msg: Mensaje en bytes a codificar.
    :param k: Longitud objetivo del bloque codificado en bytes (modulo RSA).
    :param label: Etiqueta opcional asociada al mensaje (por defecto b"").
    :return: Bloque codificado EM de longitud exacta k bytes.
    :raises TypeError: Si los argumentos no tienen los tipos esperados.
    :raises ValueError: Si k < 2*HLEN + 2 o len(msg) > k - 2*HLEN - 2.
    """
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("msg debe ser de tipo bytes o bytearray.")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label debe ser de tipo bytes o bytearray.")
    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError("k debe ser un entero.")

    # Validacion de capacidad de modulo y mensaje segun RFC 8017
    if k < 2 * HLEN + 2:
        raise ValueError(
            f"k={k} insuficiente para OAEP con SHA-256: requiere al menos {2 * HLEN + 2} bytes."
        )

    max_msg_len = k - 2 * HLEN - 2
    if len(msg) > max_msg_len:
        raise ValueError(
            f"Mensaje demasiado largo para el modulo: longitud {len(msg)} excede maximo {max_msg_len} bytes."
        )

    # 1. lHash = sha256(label)
    l_hash = sha256(bytes(label))

    # 2. Relleno PS de ceros
    ps_len = k - len(msg) - 2 * HLEN - 2
    ps = b"\x00" * ps_len

    # 3. Bloque de datos: DB = lHash || PS || 0x01 || M
    db = l_hash + ps + b"\x01" + bytes(msg)

    # 4. Generar semilla aleatoria criptografica de 32 bytes
    seed = secrets.token_bytes(HLEN)

    # 5. dbMask = MGF1(seed, k - hLen - 1)
    db_mask = mgf1(seed, k - HLEN - 1)

    # 6. maskedDB = DB ^ dbMask
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # 7. seedMask = MGF1(maskedDB, hLen)
    seed_mask = mgf1(masked_db, HLEN)

    # 8. maskedSeed = seed ^ seedMask
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # 9. EM = 0x00 || maskedSeed || maskedDB
    em = b"\x00" + masked_seed + masked_db
    return em


def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    """
    Decodifica un bloque con relleno OAEP-SHA256 y extrae el mensaje original (RFC 8017).

    :param em: Bloque codificado de exactamente k bytes.
    :param k: Longitud esperada del bloque en bytes.
    :param label: Etiqueta opcional asociada esperada.
    :return: Mensaje original en bytes.
    :raises TypeError: Si los argumentos no tienen los tipos esperados.
    :raises ValueError: DECRYPTION_ERROR ("decryption error") ante CUALQUIER fallo
                        (longitud, primer byte, lHash, separador), sin indicar la causa.

    Todas las comprobaciones se calculan siempre y se acumulan en 'malo'
    (OR de diferencias); la decision se toma una sola vez al final. Asi el
    recorrido no termina antes segun donde este el error.
    Limitacion honesta: los enteros y bytes de Python no garantizan tiempo
    constante a nivel de maquina; esto elimina las diferencias gruesas (salidas
    tempranas y mensajes distintos), no las microarquitectonicas.
    """
    if not isinstance(em, (bytes, bytearray)):
        raise TypeError("em debe ser de tipo bytes o bytearray.")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label debe ser de tipo bytes o bytearray.")
    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError("k debe ser un entero.")

    # Parametros estructurales (dependen solo de la clave, no del secreto).
    if k < 2 * HLEN + 2 or len(em) != k:
        raise ValueError(DECRYPTION_ERROR)

    # 1. Byte inicial Y: cualquier valor distinto de 0 marca error.
    malo = em[0]

    # 2. Separar maskedSeed y maskedDB y quitar las mascaras.
    masked_seed = em[1:1 + HLEN]
    masked_db = em[1 + HLEN:]
    seed_mask = mgf1(masked_db, HLEN)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - HLEN - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # 3. lHash' == lHash, comparado por acumulacion XOR.
    l_hash = sha256(bytes(label))
    for a, b in zip(db[:HLEN], l_hash):
        malo |= a ^ b

    # 4. PS || 0x01 || M: recorrer TODO el resto sin cortar.
    #    encontrado: ya vimos el primer 0x01.
    #    indice:     posicion de ese primer 0x01 (seleccion sin ramas).
    #    invalido:   aparecio un byte distinto de 0x00 y 0x01 antes del separador.
    resto = db[HLEN:]
    encontrado = 0
    indice = 0
    invalido = 0
    for i, b in enumerate(resto):
        es_uno = _ct_byte_eq(b, 0x01)
        es_cero = _ct_byte_eq(b, 0x00)
        primero = es_uno & (1 - encontrado)
        indice |= i & -primero              # -1 si primero == 1, 0 si no
        invalido |= (1 - encontrado) & (1 - es_uno) & (1 - es_cero)
        encontrado |= es_uno

    malo |= invalido | (1 - encontrado)

    # 5. Una sola decision, un solo mensaje.
    if malo != 0:
        raise ValueError(DECRYPTION_ERROR)

    # El mensaje comienza justo tras el byte 0x01
    return bytes(resto[indice + 1:])
