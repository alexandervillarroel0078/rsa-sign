"""
Nucleo aritmetico para RSA, implementado a mano.

No se usa pow() de tres argumentos ni pow(a, -1, n): el inverso modular y la
exponenciacion modular se calculan con algoritmos propios.
"""


def gcd(a: int, b: int) -> int:
    """
    Maximo comun divisor por el algoritmo de Euclides (iterativo).

    :return: gcd(a, b) siempre no negativo.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple:
    """
    Algoritmo de Euclides extendido (iterativo).

    Devuelve (g, x, y) tal que a*x + b*y == g, donde g = gcd(a, b) >= 0.
    """
    # Invariantes: old_r = a*old_x + b*old_y  y  r = a*x + b*y
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y

    # Normalizamos para que el gcd sea no negativo.
    if old_r < 0:
        old_r, old_x, old_y = -old_r, -old_x, -old_y
    return old_r, old_x, old_y


def modinv(a: int, n: int) -> int:
    """
    Inverso modular de 'a' modulo 'n' usando egcd.

    :return: x en [0, n) tal que (a * x) % n == 1.
    :raises ValueError: si n <= 0 o si gcd(a, n) != 1 (no existe inverso).
    """
    if n <= 0:
        raise ValueError("el modulo debe ser positivo")
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError(f"no existe inverso: gcd({a}, {n}) = {g}")
    return x % n


def modexp(base: int, exp: int, mod: int) -> int:
    """
    Exponenciacion modular por el metodo de cuadrar y multiplicar
    (iterativo, recorriendo los bits del exponente de menor a mayor).

    :return: (base ** exp) % mod
    :raises ValueError: si exp < 0 o mod <= 0.
    """
    if mod <= 0:
        raise ValueError("el modulo debe ser positivo")
    if exp < 0:
        raise ValueError("el exponente debe ser no negativo")
    if mod == 1:
        return 0

    result = 1
    base %= mod
    while exp > 0:
        # Si el bit actual es 1, multiplicamos el acumulado por la base.
        if exp & 1:
            result = (result * base) % mod
        # Elevamos la base al cuadrado para el siguiente bit.
        base = (base * base) % mod
        exp >>= 1
    return result
