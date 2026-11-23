"""
Implementacion de relleno PSS (Probabilistic Signature Scheme) con SHA-256.

Cumple con RFC 8017 (PKCS#1 v2.2, EMSA-PSS). Utiliza la funcion hash SHA-256
propia (src.sha256), la funcion de generacion de mascara MGF1 (src.oaep)
y el generador criptografico seguro secrets del sistema.
"""

import secrets
import sys
from pathlib import Path

try:
    from .sha256 import sha256
    from .oaep import mgf1
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.sha256 import sha256
    from src.oaep import mgf1


# Longitud en bytes de la salida de SHA-256 (256 bits = 32 bytes)
HLEN_PSS: int = 32


def emsa_pss_encode(m_hash: bytes, em_bits: int, salt_len: int = 32) -> bytes:
    """
    Codifica el resumen de un mensaje aplicando el esquema EMSA-PSS con SHA-256 (RFC 8017).

    :param m_hash: Resumen criptografico del mensaje (32 bytes para SHA-256).
    :param em_bits: Longitud objetivo de la codificacion en bits (n.bit_length() - 1).
    :param salt_len: Longitud del salt aleatorio en bytes (por defecto 32).
    :return: Bloque codificado EM de longitud exacta ceil(em_bits / 8) bytes.
    :raises TypeError: Si los parametros no tienen los tipos esperados.
    :raises ValueError: Si el modulo es insuficiente o los valores son invalidos.
    """
    if not isinstance(m_hash, (bytes, bytearray)):
        raise TypeError("m_hash debe ser de tipo bytes o bytearray.")
    if len(m_hash) != HLEN_PSS:
        raise ValueError(f"m_hash debe tener exactamente {HLEN_PSS} bytes.")
    if not isinstance(em_bits, int) or isinstance(em_bits, bool):
        raise TypeError("em_bits debe ser un entero.")
    if not isinstance(salt_len, int) or isinstance(salt_len, bool):
        raise TypeError("salt_len debe ser un entero.")
    if salt_len < 0:
        raise ValueError("salt_len no puede ser negativo.")

    # Longitud del mensaje codificado en bytes em_len = ceil(em_bits / 8)
    em_len = (em_bits + 7) // 8

    # Validar que el tamano del modulo permita alojar el relleno PSS
    if em_len < HLEN_PSS + salt_len + 2:
        raise ValueError("modulo demasiado pequeno para PSS")

    # Generar salt aleatorio criptograficamente seguro
    salt = secrets.token_bytes(salt_len) if salt_len > 0 else b""

    # M' = 0x00*8 || m_hash || salt
    m_prime = b"\x00" * 8 + bytes(m_hash) + salt

    # H = SHA-256(M')
    h = sha256(m_prime)

    # Relleno PS de ceros: longitud em_len - salt_len - HLEN_PSS - 2
    ps_len = em_len - salt_len - HLEN_PSS - 2
    ps = b"\x00" * ps_len

    # DB = PS || 0x01 || salt (longitud em_len - HLEN_PSS - 1)
    db = ps + b"\x01" + salt

    # Generar mascara dbMask = MGF1(H, em_len - HLEN_PSS - 1)
    db_mask = mgf1(h, em_len - HLEN_PSS - 1)

    # maskedDB = DB ^ dbMask
    masked_db = bytearray(a ^ b for a, b in zip(db, db_mask))

    # Limpiar los bits mas significativos de maskedDB[0] para ajustar a em_bits
    bits_a_cero = 8 * em_len - em_bits
    if bits_a_cero > 0:
        masked_db[0] &= (0xFF >> bits_a_cero)

    # EM = maskedDB || H || 0xbc (longitud exacta em_len)
    em = bytes(masked_db) + h + b"\xbc"
    return em


def emsa_pss_verify(m_hash: bytes, em: bytes, em_bits: int, salt_len: int = 32) -> bool:
    """
    Verifica la codificacion EMSA-PSS con SHA-256 de un resumen de mensaje (RFC 8017).

    :param m_hash: Resumen criptografico del mensaje (32 bytes para SHA-256).
    :param em: Bloque codificado a verificar.
    :param em_bits: Longitud esperada en bits del bloque codificado.
    :param salt_len: Longitud esperada del salt en bytes (por defecto 32).
    :return: True si la codificacion es consistente y valida, False en caso contrario.
    """
    if not isinstance(m_hash, (bytes, bytearray)) or len(m_hash) != HLEN_PSS:
        return False
    if not isinstance(em, (bytes, bytearray)):
        return False
    if not isinstance(em_bits, int) or isinstance(em_bits, bool):
        return False
    if not isinstance(salt_len, int) or isinstance(salt_len, bool) or salt_len < 0:
        return False

    em_len = len(em)
    expected_em_len = (em_bits + 7) // 8

    # Validar longitud total esperada
    if em_len != expected_em_len:
        return False

    # Validar longitud minima requerida
    if em_len < HLEN_PSS + salt_len + 2:
        return False

    # Validar byte final de parada (trailer 0xbc)
    if em[-1] != 0xBC:
        return False

    # Separar maskedDB y H
    db_len = em_len - HLEN_PSS - 1
    masked_db = em[:db_len]
    h = em[db_len:em_len - 1]

    # Validar que los bits superiores de maskedDB[0] esten en cero
    bits_a_cero = 8 * em_len - em_bits
    if bits_a_cero > 0:
        if (masked_db[0] >> (8 - bits_a_cero)) != 0:
            return False

    # Generar dbMask = MGF1(H, em_len - HLEN_PSS - 1)
    db_mask = mgf1(h, db_len)

    # Recuperar DB = maskedDB ^ dbMask
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))

    # Limpiar los bits superiores de DB[0] de la misma forma
    if bits_a_cero > 0:
        db[0] &= (0xFF >> bits_a_cero)

    # Verificar que los primeros em_len - HLEN_PSS - salt_len - 2 bytes sean 0x00
    ps_len = em_len - HLEN_PSS - salt_len - 2
    for i in range(ps_len):
        if db[i] != 0x00:
            return False

    # Verificar byte delimitador 0x01
    if db[ps_len] != 0x01:
        return False

    # Extraer salt de los ultimos salt_len bytes de DB
    salt = bytes(db[ps_len + 1:]) if salt_len > 0 else b""

    # Recalcular H' = SHA-256(0x00*8 || m_hash || salt)
    m_prime = b"\x00" * 8 + bytes(m_hash) + salt
    h_prime = sha256(m_prime)

    # Comparacion en tiempo constante de H y H' (XOR acumulado + un solo if)
    diff = 0
    for a, b in zip(h, h_prime):
        diff |= a ^ b

    return diff == 0
