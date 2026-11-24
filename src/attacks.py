"""
Modulo de Pruebas de Ataque para RSA.

Implementa:
1. Ataque de factorizacion de Fermat contra modulos RSA con primos cercanos (p ~ q).
   - Calculo de raiz cuadrada entera a mano (metodo babilonico / Newton).
   - Comprobacion de cuadrados perfectos.
   - Recuperacion completa de la clave privada d a partir de la clave publica (n, e).
2. Ataque de alteracion de 1 bit en firma digital / mensaje.
   - Demuestra la estricta integridad del esquema RSA-PSS.

Las claves usan el mismo formato que src/rsa.py: publica (n, e) y privada (n, d).
"""

from .mathcore import modinv
from .primes import generate_prime, is_probable_prime


def isqrt(n: int) -> int:
    """
    Calcula la raiz cuadrada entera de n usando el algoritmo de Newton (metodo babilonico).
    Devuelve el mayor entero s tal que s * s <= n.

    Funciona con enteros de precision arbitraria en tiempo logaritmico.
    """
    if n < 0:
        raise ValueError("No existe raiz cuadrada real para enteros negativos.")
    if n == 0:
        return 0

    # Estimacion inicial con desplazamiento de bits: 2^ceil(bits / 2)
    x = 1 << ((n.bit_length() + 1) // 2)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y


def is_square(k: int) -> tuple:
    """
    Determina si un entero k es un cuadrado perfecto.

    :param k: Entero a verificar.
    :return: (True, raiz) si k == raiz^2, o (False, 0) en caso contrario.
    """
    if k < 0:
        return False, 0
    r = isqrt(k)
    return (r * r == k), r


def fermat_factor(n: int, max_iter: int = 100000):
    """
    Factoriza un numero compuesto impar n = p * q usando el metodo de Fermat.

    Principio matematico:
    Todo impar se expresa como n = a^2 - b^2 = (a - b)(a + b).
    Si los factores p y q son proximos, 'a' estara muy cerca de ceil(sqrt(n)).
    Se prueba a = ceil(sqrt(n)), ceil(sqrt(n)) + 1, ... comprobando si a^2 - n es cuadrado.

    :param n: Modulo impar a factorizar.
    :param max_iter: Numero maximo de iteraciones.
    :return: Tupla (p, q) con p <= q, o None si no se hallo factor en el limite dado.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("n debe ser un entero impar y positivo.")

    # a inicial = ceil(sqrt(n))
    a = isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iter):
        b2 = a * a - n
        es_cuad, b = is_square(b2)
        if es_cuad:
            p = a - b
            q = a + b
            if p > 1 and q > 1:
                return (p, q) if p <= q else (q, p)
        a += 1

    return None


def fermat_attack_rsa(pub_key: tuple, max_iter: int = 100000):
    """
    Ejecuta el ataque de Fermat contra una clave publica RSA (n, e).

    Si los primos p y q fueron generados demasiado cerca, el ataque factoriza n,
    calcula phi(n) = (p - 1)*(q - 1) y deriva la clave privada d = e^(-1) mod phi(n).

    :param pub_key: Clave publica objetivo (n, e).
    :param max_iter: Limite de iteraciones de Fermat.
    :return: Tupla ((n, d), (p, q), iteraciones_realizadas) o None si el ataque falla.
    """
    n, e = pub_key

    a = isqrt(n)
    if a * a < n:
        a += 1

    for it in range(1, max_iter + 1):
        b2 = a * a - n
        es_cuad, b = is_square(b2)
        if es_cuad:
            p = a - b
            q = a + b
            if p > 1 and q > 1:
                if p > q:
                    p, q = q, p
                phi = (p - 1) * (q - 1)
                d = modinv(e, phi)
                return (n, d), (p, q), it
        a += 1

    return None


def generate_weak_fermat_key(bits: int = 512, e: int = 65537) -> tuple:
    """
    Genera deliberadamente un par de claves RSA debil con primos p y q muy cercanos,
    vulnerable al ataque de factorizacion de Fermat.

    :param bits: Longitud en bits del modulo n.
    :param e: Exponente publico.
    :return: ((n, e), (n, d)), mismo formato que rsa.generate_keypair.
    """
    half = bits // 2
    # Generamos p normalmente
    p = generate_prime(half)

    # Buscamos q inmediatamente posterior a p para que |p - q| sea minusculo
    q = p + 2
    while not is_probable_prime(q):
        q += 2

    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return (n, e), (n, d)


def corrupt_bit(data: bytes, bit_index: int = 0) -> bytes:
    """
    Invierte exactamente 1 bit en la posicion indicada de una secuencia de bytes.

    Se utiliza en las pruebas de seguridad para demostrar que una firma digital
    RSA-PSS con un solo bit alterado (en el mensaje o en la firma) es inmediatamente
    rechazada por el algoritmo de verificacion.

    :param data: Datos originales en bytes.
    :param bit_index: Posicion del bit a invertir (0-indexed).
    :return: Nuevos bytes con ese unico bit invertido.
    """
    if not data:
        raise ValueError("La secuencia de datos no puede estar vacia.")

    byte_idx = bit_index // 8
    bit_offset = bit_index % 8

    if byte_idx >= len(data):
        raise IndexError(f"bit_index={bit_index} fuera de rango para {len(data)} bytes.")

    modificado = bytearray(data)
    modificado[byte_idx] ^= (1 << bit_offset)
    return bytes(modificado)
