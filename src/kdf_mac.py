"""
HMAC-SHA256, PBKDF2-HMAC-SHA256 y cifrado autenticado de la clave privada.

Todo esta construido a mano sobre el SHA-256 propio (src/sha256.py); no se
usan hashlib ni hmac.

- hmac_sha256(key, msg)                       RFC 2104 (vectores RFC 4231)
- pbkdf2_hmac_sha256(password, salt, it, n)   RFC 8018, seccion 5.2
- encrypt_blob / decrypt_blob                 cifrado de la clave en disco:
      clave maestra = PBKDF2(contrasena, salt, iteraciones, 32)
      k_enc = HMAC(maestra, "rsa-sign/enc"), k_mac = HMAC(maestra, "rsa-sign/mac")
      flujo  = HMAC(k_enc, nonce || 0) || HMAC(k_enc, nonce || 1) || ...   (modo contador)
      ciphertext = texto XOR flujo
      tag    = HMAC(k_mac, cabecera || nonce || ciphertext)                 (encrypt-then-MAC)
  La etiqueta se comprueba en tiempo constante (acumulacion XOR) ANTES de
  descifrar; cualquier fallo da el mismo error.

Gestion de memoria (limitacion honesta): contrasena, claves derivadas y flujo
se guardan en bytearray y se sobrescriben con ceros al terminar (try/finally).
Los resultados intermedios de SHA-256 son int y bytes de Python, inmutables:
pueden quedar copias en memoria hasta que el recolector las libere.
"""

import secrets

from .sha256 import Sha256, _compress, sha256

BLOCK_SIZE = 64          # tamano de bloque de SHA-256 en bytes
DIGEST_SIZE = 32

ENC_FORMAT = "rsa-sign-encrypted-key-v1"
KDF_NAME = "pbkdf2-hmac-sha256"
CIPHER_NAME = "hmac-sha256-ctr"
MAC_NAME = "hmac-sha256"
SALT_SIZE = 16
NONCE_SIZE = 16

# Calibrado en CPython 3.10.11 / Ryzen 5 7535HS: entre ~300 y ~480 us por
# iteracion (dos compresiones SHA-256 en Python puro, segun la carga de la CPU),
# asi que 4000 iteraciones ~ 1,2 a 1,9 s por desbloqueo. OWASP (2023) recomienda
# 600 000 para PBKDF2-HMAC-SHA256: aqui serian 3 a 5 minutos. 4000 es 150 veces
# MENOS de lo recomendado: frena intentos casuales, no a un atacante con GPU que
# robe el archivo. Use una contrasena larga. El valor se guarda en cada archivo,
# asi que puede subirse sin romper los archivos existentes.
DEFAULT_ITERATIONS = 4000

AUTH_ERROR = "contrasena incorrecta o archivo de clave alterado"


def _a_bytearray(x) -> bytearray:
    """Copia str (UTF-8), bytes o bytearray a un bytearray propio (borrable)."""
    if isinstance(x, str):
        return bytearray(x.encode("utf-8"))
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytearray(x)
    raise TypeError("Se esperaba str, bytes o bytearray.")


def wipe(buf) -> None:
    """Sobrescribe un bytearray con ceros (no hace nada con bytes inmutables)."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def ct_equal(a: bytes, b: bytes) -> bool:
    """
    Comparacion sin salida temprana: acumula a[i] XOR b[i] y decide una vez.
    (La longitud no es secreta: si difiere se devuelve False.)
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


class HmacSha256:
    """
    HMAC-SHA256 con estados precalculados (RFC 2104):

        HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))

    K' es K rellenada con ceros a 64 bytes (o H(K) si K es mas larga). Los
    bloques K'^ipad y K'^opad se comprimen UNA vez al crear el objeto; cada
    mensaje solo cuesta comprimir el mensaje y un bloque externo. Esto es lo
    que hace rapido a PBKDF2 (miles de HMAC con la misma clave).
    """

    def __init__(self, key) -> None:
        k = _a_bytearray(key)
        try:
            if len(k) > BLOCK_SIZE:
                corto = bytearray(sha256(bytes(k)))
                wipe(k)
                k = corto
            k.extend(b"\x00" * (BLOCK_SIZE - len(k)))
            ipad = bytearray(b ^ 0x36 for b in k)
            opad = bytearray(b ^ 0x5C for b in k)
            try:
                self._inner = Sha256(bytes(ipad))
                self._outer = Sha256(bytes(opad))
            finally:
                wipe(ipad)
                wipe(opad)
        finally:
            wipe(k)

    def mac(self, msg: bytes) -> bytes:
        """HMAC del mensaje completo."""
        h = self._inner.copy()
        h.update(msg)
        o = self._outer.copy()
        o.update(h.digest())
        return o.digest()

    def mac32_fast(self, msg32: bytes) -> bytes:
        """
        HMAC de un mensaje de exactamente 32 bytes (bucle interno de PBKDF2).

        Tras el bloque ipad (64 bytes) quedan 32 bytes de mensaje: el ultimo
        bloque es msg || 0x80 || ceros || longitud(96 bytes = 768 bits), y lo
        mismo para el bloque externo. Se comprime directamente sin crear
        objetos: 2 compresiones por HMAC. Probado contra hmac.mac() y hashlib.
        """
        cola = b"\x80" + b"\x00" * 23 + (768).to_bytes(8, "big")
        estado = list(self._inner._state)
        _compress(estado, bytes(msg32) + cola)
        interno = b"".join(v.to_bytes(4, "big") for v in estado)
        estado = list(self._outer._state)
        _compress(estado, interno + cola)
        return b"".join(v.to_bytes(4, "big") for v in estado)


def hmac_sha256(key, msg: bytes) -> bytes:
    """HMAC-SHA256(key, msg) segun RFC 2104."""
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("msg debe ser bytes")
    return HmacSha256(key).mac(bytes(msg))


def pbkdf2_hmac_sha256(password, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """
    PBKDF2 con HMAC-SHA256 como PRF (RFC 8018, seccion 5.2):

        T_i = U_1 ^ U_2 ^ ... ^ U_c
        U_1 = PRF(P, S || INT(i)),  U_j = PRF(P, U_{j-1})
        DK  = T_1 || T_2 || ...  (truncado a dklen)

    :param password: str (UTF-8), bytes o bytearray.
    :param iterations: c >= 1.
    """
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt debe ser bytes")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
        raise ValueError("iterations debe ser un entero >= 1")
    if not isinstance(dklen, int) or dklen < 1:
        raise ValueError("dklen debe ser un entero >= 1")

    prf = HmacSha256(password)
    salida = bytearray()
    bloque = 1
    while len(salida) < dklen:
        u = prf.mac(bytes(salt) + bloque.to_bytes(4, "big"))
        t = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = prf.mac32_fast(u)
            t ^= int.from_bytes(u, "big")
        salida.extend(t.to_bytes(DIGEST_SIZE, "big"))
        bloque += 1
    resultado = bytes(salida[:dklen])
    wipe(salida)
    return resultado


def _keystream(k_enc: HmacSha256, nonce: bytes, length: int) -> bytearray:
    """Flujo de clave en modo contador: HMAC(k_enc, nonce || contador de 8 bytes)."""
    flujo = bytearray()
    contador = 0
    while len(flujo) < length:
        flujo.extend(k_enc.mac(nonce + contador.to_bytes(8, "big")))
        contador += 1
    del flujo[length:]
    return flujo


def _cabecera(iterations: int, salt: bytes) -> bytes:
    """Datos autenticados: formato y parametros, para que no se puedan cambiar."""
    return f"{ENC_FORMAT}|{KDF_NAME}|{iterations}|{CIPHER_NAME}|{MAC_NAME}|".encode() + salt


def _derivar(password, salt: bytes, iterations: int):
    """PBKDF2 -> clave maestra -> (k_enc, k_mac) separadas como objetos HMAC."""
    maestra = bytearray(pbkdf2_hmac_sha256(password, salt, iterations, DIGEST_SIZE))
    try:
        k_enc = bytearray(hmac_sha256(maestra, b"rsa-sign/enc"))
        k_mac = bytearray(hmac_sha256(maestra, b"rsa-sign/mac"))
        try:
            return HmacSha256(k_enc), HmacSha256(k_mac)
        finally:
            wipe(k_enc)
            wipe(k_mac)
    finally:
        wipe(maestra)


def encrypt_blob(plaintext: bytearray, password, iterations: int | None = None) -> dict:
    """
    Cifra y autentica 'plaintext' con una clave derivada de 'password'.

    :return: dict JSON-serializable {version, kdf, iterations, salt, cipher,
             mac, nonce, ciphertext, tag} (binarios en hex).
    """
    iterations = DEFAULT_ITERATIONS if iterations is None else iterations
    pw = _a_bytearray(password)
    if not pw:
        raise ValueError("La contrasena no puede estar vacia.")
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    flujo = bytearray()
    try:
        k_enc, k_mac = _derivar(pw, salt, iterations)
        flujo = _keystream(k_enc, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, flujo))
        tag = k_mac.mac(_cabecera(iterations, salt) + nonce + ciphertext)
    finally:
        wipe(pw)
        wipe(flujo)
    return {
        "version": ENC_FORMAT,
        "kdf": KDF_NAME,
        "iterations": iterations,
        "salt": salt.hex(),
        "cipher": CIPHER_NAME,
        "mac": MAC_NAME,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def decrypt_blob(blob: dict, password) -> bytearray:
    """
    Verifica la etiqueta y descifra. Devuelve un bytearray (el llamador debe
    borrarlo con wipe() cuando termine).

    :raises ValueError: AUTH_ERROR ante contrasena incorrecta o cualquier
                        alteracion (salt, nonce, ciphertext, tag, iteraciones).
    """
    try:
        if blob.get("version") != ENC_FORMAT or blob.get("kdf") != KDF_NAME \
                or blob.get("cipher") != CIPHER_NAME or blob.get("mac") != MAC_NAME:
            raise ValueError("formato")
        iterations = blob["iterations"]
        if not isinstance(iterations, int) or isinstance(iterations, bool) or not 1 <= iterations <= 10_000_000:
            raise ValueError("iteraciones")
        salt = bytes.fromhex(blob["salt"])
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])
        tag = bytes.fromhex(blob["tag"])
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError(AUTH_ERROR) from None

    pw = _a_bytearray(password)
    flujo = bytearray()
    try:
        k_enc, k_mac = _derivar(pw, salt, iterations)
        esperado = k_mac.mac(_cabecera(iterations, salt) + nonce + ciphertext)
        if not ct_equal(esperado, tag):
            raise ValueError(AUTH_ERROR)
        flujo = _keystream(k_enc, nonce, len(ciphertext))
        return bytearray(a ^ b for a, b in zip(ciphertext, flujo))
    finally:
        wipe(pw)
        wipe(flujo)
