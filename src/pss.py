"""
Esquema de Firma Digital RSA-PSS (PKCS#1 v2.2 / RFC 8017).

Incluye:
- Codificacion EMSA-PSS-ENCODE.
- Verificacion EMSA-PSS-VERIFY.
- Comparacion en tiempo constante para mitigar ataques de canal lateral (timing attacks).
"""

import secrets
from .sha256 import sha256
from .mgf1 import mgf1, xor_bytes
from .rsa import RSAPublicKey, RSAPrivateKey, bytes_to_int, int_to_bytes, rsa_encrypt_int, rsa_decrypt_int


# Longitud de salida de SHA-256 en bytes
HLEN = 32


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compara dos cadenas de bytes en tiempo constante para evitar ataques de canal lateral
    (timing attacks) en la verificacion de firmas.

    Recorre todos los bytes acumulando las diferencias mediante XOR y OR, sin
    retornar antes de tiempo si un byte intermedio no coincide.
    """
    if len(a) != len(b):
        return False

    diferencia = 0
    for byte_a, byte_b in zip(a, b):
        diferencia |= (byte_a ^ byte_b)

    return diferencia == 0


def emsa_pss_encode(message: bytes, em_bits: int, s_len: int = 32) -> bytes:
    """
    Codificacion EMSA-PSS-ENCODE (RFC 8017, Seccion 9.1.1).

    :param message: Mensaje en bytes a firmar.
    :param em_bits: Numero maximo de bits del mensaje codificado (mod_bits - 1).
    :param s_len: Longitud del salt en bytes (por defecto 32 bytes = hLen).
    :return: Bloque codificado EM en bytes.
    """
    em_len = (em_bits + 7) // 8

    if em_len < HLEN + s_len + 2:
        raise ValueError("Longitud de em_bits insuficiente para el esquema PSS.")

    # 1. mHash = SHA-256(message)
    m_hash = sha256(message)

    # 2. Generamos salt aleatorio con secrets
    salt = secrets.token_bytes(s_len)

    # 3. M' = 0x00(8) || mHash || salt
    m_prime = (b"\x00" * 8) + m_hash + salt

    # 4. H = SHA-256(M')
    h = sha256(m_prime)

    # 5. Generamos DB = PS || 0x01 || salt
    ps_len = em_len - s_len - HLEN - 2
    ps = b"\x00" * ps_len
    db = ps + b"\x01" + salt

    # 6. dbMask = MGF1(H, len(db))
    db_mask = mgf1(h, len(db))

    # 7. maskedDB = DB xor dbMask
    masked_db = bytearray(xor_bytes(db, db_mask))

    # 8. Limpiamos los bits no utilizados a la izquierda del primer byte
    unused_bits = (8 * em_len) - em_bits
    if unused_bits > 0:
        masked_db[0] &= (0xFF >> unused_bits)

    # 9. EM = maskedDB || H || 0xBC (0xBC es el campo de cierre del estandar)
    em = bytes(masked_db) + h + b"\xbc"
    return em


def emsa_pss_verify(message: bytes, em: bytes, em_bits: int, s_len: int = 32) -> bool:
    """
    Verificacion EMSA-PSS-VERIFY (RFC 8017, Seccion 9.1.2).

    :param message: Mensaje en bytes original.
    :param em: Bloque codificado EM recuperado.
    :param em_bits: Numero maximo de bits (mod_bits - 1).
    :param s_len: Longitud del salt esperado en bytes.
    :return: True si la firma es valida, False en caso contrario.
    """
    em_len = (em_bits + 7) // 8

    if len(em) != em_len:
        return False

    if em_len < HLEN + s_len + 2:
        return False

    # 1. Comprobar byte de parada 0xBC al final
    if em[-1] != 0xBC:
        return False

    # 2. Separar maskedDB y H
    masked_db = bytearray(em[: em_len - HLEN - 1])
    h = em[em_len - HLEN - 1 : em_len - 1]

    # 3. Comprobar que los bits sobrantes de la izquierda sean 0
    unused_bits = (8 * em_len) - em_bits
    if unused_bits > 0:
        mask = (0xFF << (8 - unused_bits)) & 0xFF
        if (masked_db[0] & mask) != 0:
            return False

    # 4. dbMask = MGF1(H, len(maskedDB))
    db_mask = mgf1(h, len(masked_db))

    # 5. DB = maskedDB xor dbMask
    db = bytearray(xor_bytes(bytes(masked_db), db_mask))

    # 6. Limpiamos los bits sobrantes de la izquierda en DB
    if unused_bits > 0:
        db[0] &= (0xFF >> unused_bits)

    # 7. Validar ceros de relleno PS y el delimitador 0x01
    ps_len = em_len - s_len - HLEN - 2
    for i in range(ps_len):
        if db[i] != 0:
            return False

    if db[ps_len] != 1:
        return False

    # 8. Extraer salt
    salt = bytes(db[-s_len:])

    # 9. Recomputar H' = SHA-256(0x00(8) || SHA-256(M) || salt)
    m_hash = sha256(message)
    m_prime = (b"\x00" * 8) + m_hash + salt
    h_prime = sha256(m_prime)

    # 10. Comparacion en tiempo constante entre H y H'
    return constant_time_compare(h, h_prime)


def rsa_sign_pss(message: bytes, priv_key: RSAPrivateKey, s_len: int = 32) -> bytes:
    """
    Genera la firma digital de un mensaje usando RSA con relleno seguro PSS.

    :param message: Mensaje en bytes a firmar.
    :param priv_key: Clave privada RSA.
    :param s_len: Longitud del salt aleatorio (por defecto 32).
    :return: Firma digital en bytes de longitud priv_key.byte_length().
    """
    k = priv_key.byte_length()
    em_bits = priv_key.bit_length() - 1
    em = emsa_pss_encode(message, em_bits, s_len)

    m_int = bytes_to_int(em)
    s_int = rsa_decrypt_int(m_int, priv_key)
    return int_to_bytes(s_int, k)


def rsa_verify_pss(message: bytes, signature: bytes, pub_key: RSAPublicKey, s_len: int = 32) -> bool:
    """
    Verifica una firma digital RSA-PSS utilizando comparacion en tiempo constante.

    :param message: Mensaje original en bytes.
    :param signature: Firma en bytes a verificar.
    :param pub_key: Clave publica RSA.
    :param s_len: Longitud del salt.
    :return: True si la firma es autentica e integra, False si es invalida o corrupta.
    """
    k = pub_key.byte_length()
    if len(signature) != k:
        return False

    s_int = bytes_to_int(signature)
    if s_int >= pub_key.n:
        return False

    m_int = rsa_encrypt_int(s_int, pub_key)
    em_bits = pub_key.bit_length() - 1
    em_len = (em_bits + 7) // 8

    em = int_to_bytes(m_int, em_len)
    return emsa_pss_verify(message, em, em_bits, s_len)
