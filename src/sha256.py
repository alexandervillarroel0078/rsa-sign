"""
Implementacion propia de SHA-256 segun FIPS 180-4.

No utiliza hashlib ni ninguna libreria criptografica externa. Todas las
operaciones se realizan sobre enteros de 32 bits aplicando la mascara
0xFFFFFFFF tras cada suma o desplazamiento.
"""

# Mascara para mantener los valores dentro de 32 bits.
MASK32 = 0xFFFFFFFF

# 64 constantes K (FIPS 180-4, seccion 4.2.2): primeros 32 bits de la parte
# fraccionaria de las raices cubicas de los primeros 64 numeros primos.
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# 8 valores iniciales H (FIPS 180-4, seccion 5.3.3): primeros 32 bits de la
# parte fraccionaria de las raices cuadradas de los primeros 8 primos.
H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)


def _rotr(x: int, n: int) -> int:
    """Rotacion circular a la derecha de n bits sobre una palabra de 32 bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _ch(x: int, y: int, z: int) -> int:
    """Funcion Ch: para cada bit, si x es 1 elige y, si no elige z."""
    return (x & y) ^ ((~x & MASK32) & z)


def _maj(x: int, y: int, z: int) -> int:
    """Funcion Maj: para cada bit devuelve el valor mayoritario de x, y, z."""
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
    """Funcion Sigma0 (mayuscula), usada sobre la variable de trabajo 'a'."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x: int) -> int:
    """Funcion Sigma1 (mayuscula), usada sobre la variable de trabajo 'e'."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _small_sigma0(x: int) -> int:
    """Funcion sigma0 (minuscula), usada en la expansion del mensaje."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _small_sigma1(x: int) -> int:
    """Funcion sigma1 (minuscula), usada en la expansion del mensaje."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _pad(data: bytes) -> bytes:
    """
    Aplica el relleno de FIPS 180-4 (seccion 5.1.1).

    Se agrega un bit '1' (byte 0x80), luego ceros hasta que la longitud sea
    congruente con 448 mod 512 bits (56 mod 64 bytes) y finalmente la
    longitud original del mensaje en bits como entero big-endian de 64 bits.
    """
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(data)
    padded.append(0x80)
    # Ceros hasta dejar exactamente 8 bytes libres al final del bloque.
    padded.extend(b"\x00" * ((56 - len(padded) % 64) % 64))
    padded.extend(bit_len.to_bytes(8, "big"))
    return bytes(padded)


def _compress(state: list, block: bytes) -> None:
    """
    Procesa un bloque de 512 bits (64 bytes) y actualiza 'state' en sitio.
    """
    # Preparacion del calendario de mensaje W[0..63].
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        w.append(
            (_small_sigma1(w[t - 2]) + w[t - 7]
             + _small_sigma0(w[t - 15]) + w[t - 16]) & MASK32
        )

    # Inicializacion de las variables de trabajo con el estado actual.
    a, b, c, d, e, f, g, h = state

    # 64 rondas de compresion.
    for t in range(64):
        t1 = (h + _big_sigma1(e) + _ch(e, f, g) + K[t] + w[t]) & MASK32
        t2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK32

    # Suma del resultado al estado intermedio.
    for i, v in enumerate((a, b, c, d, e, f, g, h)):
        state[i] = (state[i] + v) & MASK32


class Sha256:
    """
    SHA-256 incremental (streaming): update() varias veces y digest() al final.

    Permite resumir archivos grandes por bloques sin cargarlos enteros en
    memoria. El resultado es identico a sha256(datos_concatenados).
    copy() duplica el estado intermedio (lo usa HMAC para precalcular).
    """

    def __init__(self, data: bytes = b"") -> None:
        self._state = list(H0)        # H0..H7 actuales
        self._buffer = bytearray()    # bytes pendientes (< 64)
        self._length = 0              # longitud total procesada en bytes
        if data:
            self.update(data)

    def update(self, data: bytes) -> "Sha256":
        """Agrega datos al resumen. Procesa cada bloque completo de 64 bytes."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data debe ser bytes")
        data = bytes(data)
        self._length += len(data)
        buf = self._buffer
        buf.extend(data)
        completos = len(buf) - (len(buf) % 64)
        for i in range(0, completos, 64):
            _compress(self._state, bytes(buf[i:i + 64]))
        del buf[:completos]
        return self

    def copy(self) -> "Sha256":
        """Devuelve una copia independiente del estado intermedio."""
        otro = Sha256.__new__(Sha256)
        otro._state = list(self._state)
        otro._buffer = bytearray(self._buffer)
        otro._length = self._length
        return otro

    def digest(self) -> bytes:
        """
        Resumen de 32 bytes de todo lo agregado. No modifica el objeto:
        aplica el relleno FIPS 180-4 sobre una copia del estado.
        """
        state = list(self._state)
        bit_len = (self._length * 8) & 0xFFFFFFFFFFFFFFFF
        cola = bytearray(self._buffer)
        cola.append(0x80)
        cola.extend(b"\x00" * ((56 - len(cola) % 64) % 64))
        cola.extend(bit_len.to_bytes(8, "big"))
        for i in range(0, len(cola), 64):
            _compress(state, bytes(cola[i:i + 64]))
        # Concatenacion big-endian de las 8 palabras finales.
        return b"".join(v.to_bytes(4, "big") for v in state)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    """
    Calcula el resumen SHA-256 de 'data'.

    :param data: mensaje de entrada en bytes.
    :return: resumen de 32 bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes")

    state = list(H0)
    padded = _pad(bytes(data))
    # Procesamiento bloque por bloque (512 bits = 64 bytes).
    for i in range(0, len(padded), 64):
        _compress(state, padded[i:i + 64])

    # Concatenacion big-endian de las 8 palabras finales.
    return b"".join(v.to_bytes(4, "big") for v in state)


def sha256_file(path, chunk_size: int = 64 * 1024) -> bytes:
    """
    SHA-256 de un archivo leido por bloques de 'chunk_size' bytes (streaming).

    La memoria usada no depende del tamano del archivo.
    """
    h = Sha256()
    with open(path, "rb") as f:
        while True:
            bloque = f.read(chunk_size)
            if not bloque:
                break
            h.update(bloque)
    return h.digest()


def sha256_hex(data: bytes) -> str:
    """
    Calcula el resumen SHA-256 de 'data' y lo devuelve en hexadecimal.

    :param data: mensaje de entrada en bytes.
    :return: cadena hexadecimal de 64 caracteres en minusculas.
    """
    return sha256(data).hex()
