"""
Generacion de pares de claves RSA, cifrado, descifrado y gestion de claves.

Implementacion pura en Python sin librerias criptograficas externas.
Utiliza modinv, modexp y gcd de mathcore y generate_prime de primes.
"""

import json
import os
import secrets
import sys
import warnings
from pathlib import Path

# Soporte para ejecucion tanto como modulo (python -m src.rsa)
# como ejecucion directa como script (python src/rsa.py).
try:
    from .mathcore import gcd, modexp, modinv
    from .primes import generate_prime
    from .oaep import DECRYPTION_ERROR, oaep_decode, oaep_encode
    from .pss import emsa_pss_encode, emsa_pss_verify
    from .sha256 import sha256
    from . import kdf_mac
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.mathcore import gcd, modexp, modinv
    from src.primes import generate_prime
    from src.oaep import DECRYPTION_ERROR, oaep_decode, oaep_encode
    from src.pss import emsa_pss_encode, emsa_pss_verify
    from src.sha256 import sha256
    from src import kdf_mac


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


class LegacyKeyFormatWarning(UserWarning):
    """Se cargo una clave privada en el formato antiguo {n, d} (sin CRT)."""


class RSAPrivateKey(tuple):
    """
    Clave privada RSA.

    Es una tupla (n, d), igual que el formato original, por lo que
    'n, d = clave' y 'clave == (n, d)' siguen funcionando. Ademas guarda como
    atributos los parametros del Teorema Chino del Resto (PKCS #1, RFC 8017 3.2):

        e     exponente publico (necesario para blinding y para la
              comprobacion de la firma); None si se desconoce
        p, q  factores primos de n
        dp    d mod (p - 1)
        dq    d mod (q - 1)
        qinv  q^(-1) mod p (calculado con el algoritmo extendido de Euclides)

    Si p y q son None, la clave no tiene CRT y se usa m = c^d mod n.
    """

    def __new__(cls, n: int, d: int, e: int | None = None, p: int | None = None,
                q: int | None = None, dp: int | None = None, dq: int | None = None,
                qinv: int | None = None):
        obj = super().__new__(cls, (n, d))
        obj.e, obj.p, obj.q, obj.dp, obj.dq, obj.qinv = e, p, q, dp, dq, qinv
        obj.legacy = False
        return obj

    @classmethod
    def from_primes(cls, p: int, q: int, e: int = E_DEFAULT) -> "RSAPrivateKey":
        """Construye la clave completa a partir de p, q y e."""
        n = p * q
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)                      # d = e^(-1) mod phi(n), por AEE
        return cls(n, d, e=e, p=p, q=q,
                   dp=d % (p - 1),              # dP = d mod (p - 1)
                   dq=d % (q - 1),              # dQ = d mod (q - 1)
                   qinv=modinv(q, p))           # qInv = q^(-1) mod p, por AEE

    @property
    def n(self) -> int:
        return self[0]

    @property
    def d(self) -> int:
        return self[1]

    @property
    def has_crt(self) -> bool:
        return self.p is not None

    def public_key(self) -> tuple[int, int]:
        """(n, e) si se conoce e."""
        if self.e is None:
            raise ValueError("La clave privada no incluye el exponente publico e.")
        return (self.n, self.e)

    def check(self) -> None:
        """
        Comprueba la coherencia de los parametros (Zero-Trust al cargar).

        :raises ValueError: si p*q != n, e*d != 1 mod lcm(p-1, q-1) o algun
                            parametro CRT no corresponde a d, p y q.
        """
        n, d = self
        if self.has_crt:
            p, q = self.p, self.q
            if p * q != n or p < 3 or q < 3:
                raise ValueError("Clave privada incoherente: p * q != n.")
            lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
            if self.e is not None and (self.e * d) % lam != 1:
                raise ValueError("Clave privada incoherente: e * d != 1 (mod lambda(n)).")
            if self.dp != d % (p - 1) or self.dq != d % (q - 1) or (self.qinv * q) % p != 1:
                raise ValueError("Clave privada incoherente: parametros CRT invalidos.")

    def __repr__(self) -> str:
        # No se muestran d, p ni q para que no terminen en logs o trazas.
        return f"RSAPrivateKey(bits={self.n.bit_length()}, crt={self.has_crt}, legacy={self.legacy})"

    __str__ = __repr__


def _clave_e(private) -> int | None:
    """Exponente publico asociado a la clave privada, si se conoce."""
    return getattr(private, "e", None)


def rsa_private_op(c: int, private: tuple[int, int], use_crt: bool = True,
                   blinding: bool = True) -> int:
    """
    Operacion con clave privada m = c^d mod n (RSADP / RSASP1 de RFC 8017).

    1. Blinding (si se conoce e): se elige r aleatorio con gcd(r, n) = 1 y se
       opera sobre c' = c * r^e mod n. El resultado es m' = m * r, y se
       devuelve m = m' * r^(-1) mod n. Asi el tiempo de la exponenciacion no
       depende del c que eligio el atacante (contramedida contra ataques de
       temporizacion tipo Kocher).
    2. CRT con recombinacion de Garner (si la clave tiene p y q):
           m1 = c'^dP mod p,   m2 = c'^dQ mod q
           h  = qInv * (m1 - m2) mod p
           m  = m2 + h * q
       Dos exponenciaciones con modulos y exponentes de la mitad de bits:
       en teoria unas 4 veces mas rapido que c^d mod n.
    3. Sin CRT: m = c^d mod n (cuadrar y multiplicar).

    :param c: entero 0 <= c < n.
    :param use_crt: permite desactivar CRT (comparaciones y benchmark).
    :param blinding: permite desactivar el blinding (pruebas).
    """
    n, d = _validate_private_key(private)
    if not 0 <= c < n:
        raise ValueError("El entero de entrada debe cumplir 0 <= c < n.")
    e = _clave_e(private)

    r_inv = None
    if blinding and e is not None:
        while True:
            r = 2 + secrets.randbelow(n - 3)
            if gcd(r, n) == 1:
                break
        c = (c * modexp(r, e, n)) % n
        r_inv = modinv(r, n)

    if use_crt and getattr(private, "p", None) is not None:
        p, q = private.p, private.q
        m1 = modexp(c % p, private.dp, p)
        m2 = modexp(c % q, private.dq, q)
        h = (private.qinv * (m1 - m2)) % p
        m = m2 + h * q
    else:
        m = modexp(c, d, n)

    if r_inv is not None:
        m = (m * r_inv) % n
    return m


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
    :return: Tupla ((n, e), clave_privada). clave_privada es un RSAPrivateKey: se
             comporta como la tupla (n, d) y ademas lleva e, p, q, dP, dQ, qInv para CRT.
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

            encontrado = True
            break

        if encontrado:
            break

    # Clave publica: (n, e)
    public_key = (n, e)
    # Clave privada: tupla (n, d) con parametros CRT; d = e^(-1) mod phi(n)
    private_key = RSAPrivateKey.from_primes(p, q, e)

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

    # m = c^d (mod n), con CRT y blinding si la clave los admite
    m = rsa_private_op(c, private)

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

    # m = c^d (mod n), con CRT y blinding si la clave los admite
    m = rsa_private_op(c, private)
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
    entero m y calcula s = m^d (mod n) con rsa_private_op (CRT + blinding si la
    clave los admite). Si se conoce e, comprueba s^e mod n == EM. Devuelve k bytes.
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
    s = rsa_private_op(m, private)

    # Proteccion contra fallos (ataque de Bellcore / Boneh-DeMillo-Lipton):
    # si un error de calculo afectara a una de las dos mitades del CRT, la
    # firma defectuosa permitiria factorizar n con gcd(s'^e - m, n). Por eso
    # se comprueba s^e mod n == EM antes de entregar la firma.
    e = _clave_e(private)
    if e is not None and modexp(s, e, n) != m:
        raise ValueError("Error interno al firmar: la firma no verifica (posible fallo de calculo).")

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


PRIVATE_KEY_FORMAT_V2 = "rsa-sign-private-v2"
_CAMPOS_V2 = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")


def private_key_to_dict(private: tuple[int, int]) -> dict:
    """
    Serializa la clave privada a un diccionario JSON (enteros en hex '0x...').

    Formato v2: {"format": "rsa-sign-private-v2", n, e, d, p, q, dp, dq, qinv}.
    Una tupla (n, d) sin CRT se serializa con los campos disponibles.
    """
    n, d = _validate_private_key(private)
    data = {"format": PRIVATE_KEY_FORMAT_V2, "n": hex(n), "d": hex(d)}
    for campo in ("e", "p", "q", "dp", "dq", "qinv"):
        valor = getattr(private, campo, None)
        if valor is not None:
            data[campo] = hex(valor)
    return data


def _hex_a_int(data: dict, campo: str) -> int:
    valor = data[campo]
    if not isinstance(valor, str):
        raise ValueError(f"El campo '{campo}' debe ser una cadena hexadecimal.")
    try:
        x = int(valor, 16)
    except ValueError as err:
        raise ValueError(f"Formato hexadecimal invalido en clave privada ('{campo}'): {err}") from err
    if x <= 0:
        raise ValueError("Los componentes de la clave privada deben ser enteros positivos.")
    return x


def private_key_from_dict(data: dict) -> RSAPrivateKey:
    """
    Reconstruye la clave privada desde un diccionario (formato v2 o antiguo).

    - v2 (con p y q): se reconstruye con CRT y se comprueba su coherencia.
    - Antiguo {n, d}: se acepta sin CRT, con e = 65537 por defecto, y se emite
      LegacyKeyFormatWarning. Antes de usar e para blinding se comprueba que
      (r^e)^d = r mod n; si no se cumple, e se descarta (sin blinding).
    """
    if not isinstance(data, dict):
        raise ValueError("El contenido del JSON debe ser un diccionario.")
    if "n" not in data or "d" not in data:
        raise ValueError("El JSON de clave privada debe contener los campos 'n' y 'd'.")
    n, d = _hex_a_int(data, "n"), _hex_a_int(data, "d")

    if all(campo in data for campo in _CAMPOS_V2):
        valores = {campo: _hex_a_int(data, campo) for campo in _CAMPOS_V2}
        clave = RSAPrivateKey(**valores)
        clave.check()
        return clave

    # Formato antiguo: sin CRT.
    e = _hex_a_int(data, "e") if "e" in data else E_DEFAULT
    clave = RSAPrivateKey(n, d, e=e)
    r = 2 + secrets.randbelow(n - 3) if n > 4 else 2
    if modexp(modexp(r, e, n), d, n) != r % n:
        clave.e = None  # e no corresponde a d: sin blinding ni comprobacion de firma
    clave.legacy = True
    warnings.warn(
        "Clave privada en formato antiguo {n, d}: no incluye p ni q, se usa sin CRT. "
        "Genere un par nuevo (keygen) para tener CRT y la clave cifrada con contrasena.",
        LegacyKeyFormatWarning,
        stacklevel=3,
    )
    return clave


def _escribir_privado(path: str | Path, texto: str) -> None:
    """
    Escribe un archivo con permisos 0o600 (solo el propietario lee y escribe).

    En POSIX se crea ya con esos permisos (os.open) y se reajusta con chmod por
    si el archivo existia. En Windows chmod solo controla "solo lectura": los
    permisos reales dependen de las ACL de la carpeta del usuario; el error se
    ignora a proposito.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(texto)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_private_key(private: tuple[int, int], path: str | Path, password=None,
                     insecure_plain: bool = False, iterations: int | None = None) -> None:
    """
    Guarda una clave privada RSA en un archivo JSON.

    Por defecto la clave se guarda CIFRADA con la contrasena (src/kdf_mac.py):
    PBKDF2-HMAC-SHA256 -> claves separadas de cifrado y MAC -> flujo HMAC en
    modo contador + etiqueta HMAC-SHA256 (encrypt-then-MAC). El archivo
    contiene: version, kdf, iterations, salt, cipher, mac, nonce, ciphertext, tag.

    insecure_plain=True guarda el formato v2 SIN cifrar (n, e, d, p, q, dp, dq,
    qinv en hex). Solo para tests y demostraciones.

    En ambos casos el archivo se crea con permisos 0o600 (ver _escribir_privado).

    :param private: RSAPrivateKey o tupla (n, d).
    :param path: Ruta del archivo donde guardar la clave (str o Path).
    :param password: str, bytes o bytearray (el bytearray se sobrescribe con ceros).
    :param insecure_plain: guarda sin cifrar (requiere password=None).
    :param iterations: iteraciones de PBKDF2 (por defecto kdf_mac.DEFAULT_ITERATIONS).
    :raises ValueError: si no hay contrasena y no se pidio insecure_plain.
    """
    data = private_key_to_dict(private)
    if insecure_plain:
        if password is not None:
            raise ValueError("Indique password o insecure_plain=True, no ambos.")
        _escribir_privado(path, json.dumps(data, indent=2))
        return
    if password is None:
        raise ValueError("Se requiere una contrasena para guardar la clave privada "
                         "(o insecure_plain=True solo para pruebas).")
    plano = bytearray(json.dumps(data).encode("utf-8"))
    try:
        blob = kdf_mac.encrypt_blob(plano, password, iterations=iterations)
    finally:
        kdf_mac.wipe(plano)
    _escribir_privado(path, json.dumps(blob, indent=2))


def is_encrypted_key_file(path: str | Path) -> bool:
    """True si el archivo es una clave privada cifrada con contrasena."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("version") == kdf_mac.ENC_FORMAT


def load_private_key(path: str | Path, password=None) -> RSAPrivateKey:
    """
    Carga una clave privada RSA desde un archivo JSON.

    Formatos aceptados:
    - Cifrado con contrasena (rsa-sign-encrypted-key-v1): requiere password.
    - v2 sin cifrar (n, e, d, p, q, dp, dq, qinv).
    - Antiguo {n, d}: sin CRT, con aviso LegacyKeyFormatWarning.

    :param path: Ruta del archivo JSON a cargar (str o Path).
    :param password: contrasena si el archivo esta cifrado.
    :return: RSAPrivateKey (se comporta como la tupla (n, d)).
    :raises FileNotFoundError: Si el archivo no existe.
    :raises ValueError: Si el archivo esta corrupto, falta la contrasena, la
                        contrasena es incorrecta, el archivo fue alterado o la
                        clave es incoherente.
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

    if isinstance(data, dict) and data.get("version") == kdf_mac.ENC_FORMAT:
        if password is None:
            raise ValueError("La clave privada esta cifrada: se requiere la contrasena.")
        plano = kdf_mac.decrypt_blob(data, password)
        try:
            interno = json.loads(plano.decode("utf-8"))
        except ValueError:
            raise ValueError(kdf_mac.AUTH_ERROR) from None
        finally:
            kdf_mac.wipe(plano)
        return private_key_from_dict(interno)

    return private_key_from_dict(data)


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
