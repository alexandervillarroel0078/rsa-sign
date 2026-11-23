"""
MGF1: Mask Generation Function 1 (RFC 8017 / PKCS#1 v2.2).

Genera una mascara determinista de longitud arbitraria a partir de una semilla
utilizando la funcion hash SHA-256 propia de src/sha256.py.
"""

from .sha256 import sha256


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Realiza la operacion XOR byte a byte entre dos cadenas de bytes de igual longitud.
    """
    if len(a) != len(b):
        raise ValueError("Las secuencias de bytes deben tener la misma longitud para XOR.")
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """
    Funcion generadora de mascara MGF1 basada en SHA-256 (RFC 8017, Seccion B.2.1).

    :param seed: Semilla de entrada (bytes).
    :param mask_len: Longitud deseada de la mascara resultante en bytes.
    :return: Mascara pseudoaleatoria de longitud 'mask_len'.
    """
    if mask_len < 0:
        raise ValueError("La longitud de la mascara debe ser no negativa.")

    mask = bytearray()
    counter = 0

    # Cada iteracion con SHA-256 genera un bloque de 32 bytes (hLen = 32)
    while len(mask) < mask_len:
        # C = I2OSP(counter, 4): contador de 4 bytes en formato big-endian
        c = counter.to_bytes(4, byteorder="big")
        # Concatenamos semilla y contador y aplicamos SHA-256
        bloque = sha256(seed + c)
        mask.extend(bloque)
        counter += 1

    return bytes(mask[:mask_len])
