"""
Relleno OAEP (Optimal Asymmetric Encryption Padding) segun PKCS#1 v2.2 / RFC 8017.

Proporciona cifrado probabilisticamente seguro (IND-CCA2) para RSA combinando
la funcion hash SHA-256 y la mascara MGF1.
"""

import secrets
from .sha256 import sha256
from .mgf1 import mgf1, xor_bytes
from .rsa import RSAPublicKey, RSAPrivateKey, bytes_to_int, int_to_bytes, rsa_encrypt_int, rsa_decrypt_int


# Longitud de salida de SHA-256 en bytes
HLEN = 32


def oaep_encode(message: bytes, em_len: int, label: bytes = b"") -> bytes:
    """
    Aplica el relleno EME-OAEP-ENCODE a un mensaje de texto plano.

    :param message: Mensaje en bytes a codificar.
    :param em_len: Longitud total del bloque codificado (k = bytes del modulo n).
    :param label: Etiqueta opcional asociada (por defecto vacia).
    :return: Bloque codificado EM de longitud em_len.
    """
    m_len = len(message)
    # Longitud maxima permitida segun RFC 8017
    max_len = em_len - 2 * HLEN - 2
    if m_len > max_len:
        raise ValueError(
            f"Mensaje demasiado largo ({m_len} bytes). Maximo para esta clave: {max_len} bytes."
        )

    # 1. lHash = SHA-256(label)
    l_hash = sha256(label)

    # 2. Relleno de ceros PS
    ps_len = em_len - m_len - 2 * HLEN - 2
    ps = b"\x00" * ps_len

    # 3. DB = lHash || PS || 0x01 || M
    db = l_hash + ps + b"\x01" + message

    # 4. Generamos una semilla aleatoria de 32 bytes con secrets (CSPRNG)
    seed = secrets.token_bytes(HLEN)

    # 5. dbMask = MGF1(seed, len(db))
    db_mask = mgf1(seed, len(db))

    # 6. maskedDB = DB xor dbMask
    masked_db = xor_bytes(db, db_mask)

    # 7. seedMask = MGF1(maskedDB, HLEN)
    seed_mask = mgf1(masked_db, HLEN)

    # 8. maskedSeed = seed xor seedMask
    masked_seed = xor_bytes(seed, seed_mask)

    # 9. EM = 0x00 || maskedSeed || maskedDB
    em = b"\x00" + masked_seed + masked_db
    return em


def oaep_decode(em: bytes, label: bytes = b"") -> bytes:
    """
    Decodifica y valida el relleno EME-OAEP-DECODE devolviendo el mensaje original.

    :param em: Bloque codificado de longitud k.
    :param label: Etiqueta opcional asociada.
    :return: Mensaje original en bytes.
    :raises ValueError: Si el formato del relleno es incorrecto.
    """
    if len(em) < 2 * HLEN + 2:
        raise ValueError("Longitud insuficiente para decodificacion OAEP.")

    # El primer byte debe ser 0x00
    first_byte = em[0]

    # Separamos maskedSeed y maskedDB
    masked_seed = em[1 : 1 + HLEN]
    masked_db = em[1 + HLEN :]

    # 1. Recuperamos seed
    seed_mask = mgf1(masked_db, HLEN)
    seed = xor_bytes(masked_seed, seed_mask)

    # 2. Recuperamos DB
    db_mask = mgf1(seed, len(masked_db))
    db = xor_bytes(masked_db, db_mask)

    # 3. Verificamos lHash
    l_hash = sha256(label)
    db_lhash = db[:HLEN]

    # 4. Buscamos el separador 0x01 despues de los ceros de relleno PS
    rest = db[HLEN:]
    idx = 0
    while idx < len(rest) and rest[idx] == 0:
        idx += 1

    # Verificacion estricta de estructura
    if first_byte != 0 or db_lhash != l_hash or idx >= len(rest) or rest[idx] != 1:
        raise ValueError("Relleno OAEP invalido o mensaje corrupto.")

    # El mensaje original comienza inmediatamente despues del byte 0x01
    return rest[idx + 1 :]


def rsa_encrypt_oaep(message: bytes, pub_key: RSAPublicKey, label: bytes = b"") -> bytes:
    """
    Cifra un mensaje usando RSA con relleno seguro OAEP.

    :param message: Bytes a cifrar.
    :param pub_key: Clave publica RSA.
    :param label: Etiqueta opcional.
    :return: Texto cifrado en bytes de longitud pub_key.byte_length().
    """
    k = pub_key.byte_length()
    em = oaep_encode(message, k, label)
    m_int = bytes_to_int(em)
    c_int = rsa_encrypt_int(m_int, pub_key)
    return int_to_bytes(c_int, k)


def rsa_decrypt_oaep(ciphertext: bytes, priv_key: RSAPrivateKey, label: bytes = b"") -> bytes:
    """
    Descifra un criptograma usando RSA con decodificacion OAEP.

    :param ciphertext: Bytes cifrados.
    :param priv_key: Clave privada RSA.
    :param label: Etiqueta opcional con la que se cifro.
    :return: Mensaje original en bytes.
    """
    k = priv_key.byte_length()
    if len(ciphertext) != k:
        raise ValueError(f"Longitud del criptograma ({len(ciphertext)}) no coincide con la clave ({k}).")

    c_int = bytes_to_int(ciphertext)
    m_int = rsa_decrypt_int(c_int, priv_key)
    em = int_to_bytes(m_int, k)
    return oaep_decode(em, label)
