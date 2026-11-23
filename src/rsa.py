"""
Modulo RSA: Generacion de claves, cifrado y descifrado basico, y persistencia.

Implementado a mano para el Proyecto 2 de Criptografia.
Utiliza modexp y modinv de src/mathcore.py y generate_prime de src/primes.py.
Sin dependencias externas de criptografia.
"""

from .mathcore import gcd, modexp, modinv
from .primes import generate_prime


class RSAPublicKey:
    """Clave publica RSA compuesta por el modulo n y el exponente publico e."""

    def __init__(self, n: int, e: int = 65537):
        self.n = n
        self.e = e

    def bit_length(self) -> int:
        """Devuelve la longitud en bits del modulo n."""
        return self.n.bit_length()

    def byte_length(self) -> int:
        """Devuelve la longitud en bytes del modulo n."""
        return (self.n.bit_length() + 7) // 8

    def __repr__(self) -> str:
        return f"<RSAPublicKey bits={self.bit_length()} e={self.e}>"


class RSAPrivateKey:
    """Clave privada RSA compuesta por n, d y opcionalmente los factores p y q."""

    def __init__(self, n: int, d: int, e: int = 65537, p: int = 0, q: int = 0):
        self.n = n
        self.d = d
        self.e = e
        self.p = p
        self.q = q

    def bit_length(self) -> int:
        """Devuelve la longitud en bits del modulo n."""
        return self.n.bit_length()

    def byte_length(self) -> int:
        """Devuelve la longitud en bytes del modulo n."""
        return (self.n.bit_length() + 7) // 8

    def public_key(self) -> RSAPublicKey:
        """Obtiene la clave publica asociada."""
        return RSAPublicKey(self.n, self.e)

    def __repr__(self) -> str:
        return f"<RSAPrivateKey bits={self.bit_length()} e={self.e}>"


def bytes_to_int(data: bytes) -> int:
    """Convierte una secuencia de bytes en entero (big-endian)."""
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(number: int, length: int) -> bytes:
    """Convierte un entero en bytes de longitud fija (big-endian)."""
    return number.to_bytes(length, byteorder="big")


def generate_keypair(bits: int = 1024, e: int = 65537) -> tuple:
    """
    Genera un par de claves RSA (publica, privada) con un modulo de 'bits' bits.

    1. Genera dos primos p y q de aproximadamente bits // 2 bits.
    2. Calcula el modulo n = p * q.
    3. Calcula phi(n) = (p - 1) * (q - 1).
    4. Comprueba que gcd(e, phi) == 1.
    5. Calcula el exponente privado d = modinv(e, phi).

    :param bits: Tamano deseado del modulo n en bits (minimo 64).
    :param e: Exponente publico (por defecto 65537).
    :return: (RSAPublicKey, RSAPrivateKey)
    """
    if bits < 64:
        raise ValueError("El tamano de bits debe ser de al menos 64.")

    half_bits = bits // 2

    while True:
        # Generamos dos primos independientes usando Miller-Rabin
        p = generate_prime(half_bits)
        q = generate_prime(bits - half_bits)

        if p == q:
            continue

        n = p * q
        # Aseguramos que el producto tenga exactamente la cantidad de bits solicitada
        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)

        # e debe ser coprimo con phi(n)
        if gcd(e, phi) == 1:
            try:
                d = modinv(e, phi)
                pub = RSAPublicKey(n, e)
                priv = RSAPrivateKey(n, d, e, p, q)
                return pub, priv
            except ValueError:
                continue


def rsa_encrypt_int(m: int, pub_key: RSAPublicKey) -> int:
    """
    Cifrado basico RSA sobre enteros (libro de texto): c = m^e mod n.
    """
    if m < 0 or m >= pub_key.n:
        raise ValueError("El mensaje entero m debe cumplir 0 <= m < n.")
    return modexp(m, pub_key.e, pub_key.n)


def rsa_decrypt_int(c: int, priv_key: RSAPrivateKey) -> int:
    """
    Descifrado basico RSA sobre enteros (libro de texto): m = c^d mod n.
    """
    if c < 0 or c >= priv_key.n:
        raise ValueError("El texto cifrado c debe cumplir 0 <= c < n.")
    return modexp(c, priv_key.d, priv_key.n)


def save_public_key(pub_key: RSAPublicKey, filepath: str) -> None:
    """
    Guarda la clave publica en un archivo de texto con formato legible estilo PEM.
    """
    content = (
        "-----BEGIN RSA PUBLIC KEY-----\n"
        f"n: {hex(pub_key.n)}\n"
        f"e: {hex(pub_key.e)}\n"
        "-----END RSA PUBLIC KEY-----\n"
    )
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)


def load_public_key(filepath: str) -> RSAPublicKey:
    """
    Carga una clave publica guardada en formato PEM legible.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    n = None
    e = None
    for line in lines:
        if line.startswith("n:"):
            n = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("e:"):
            e = int(line.split(":", 1)[1].strip(), 16)

    if n is None or e is None:
        raise ValueError("Archivo de clave publica con formato invalido.")

    return RSAPublicKey(n, e)


def save_private_key(priv_key: RSAPrivateKey, filepath: str) -> None:
    """
    Guarda la clave privada en un archivo de texto con formato legible estilo PEM.
    """
    content = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"n: {hex(priv_key.n)}\n"
        f"e: {hex(priv_key.e)}\n"
        f"d: {hex(priv_key.d)}\n"
        f"p: {hex(priv_key.p)}\n"
        f"q: {hex(priv_key.q)}\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)


def load_private_key(filepath: str) -> RSAPrivateKey:
    """
    Carga una clave privada guardada en formato PEM legible.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    n = None
    e = 65537
    d = None
    p = 0
    q = 0
    for line in lines:
        if line.startswith("n:"):
            n = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("e:"):
            e = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("d:"):
            d = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("p:"):
            p = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("q:"):
            q = int(line.split(":", 1)[1].strip(), 16)

    if n is None or d is None:
        raise ValueError("Archivo de clave privada con formato invalido.")

    return RSAPrivateKey(n, d, e, p, q)
