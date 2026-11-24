"""
Generacion y prueba de primalidad para RSA.

La aritmetica modular se delega en src/mathcore.py (modexp). La aleatoriedad
proviene exclusivamente de 'secrets'.
"""

import secrets

from .mathcore import modexp


def _sieve(limit: int) -> list:
    """
    Criba de Eratostenes simple: devuelve los primos menores que 'limit'.
    """
    es_primo = [True] * limit
    es_primo[0] = es_primo[1] = False
    i = 2
    while i * i < limit:
        if es_primo[i]:
            # Tachamos los multiplos de i empezando en i*i.
            for j in range(i * i, limit, i):
                es_primo[j] = False
        i += 1
    return [n for n in range(limit) if es_primo[n]]


# Primos menores a 1000, usados para casos base y division de prueba.
SMALL_PRIMES = _sieve(1000)
_SMALL_PRIMES_SET = frozenset(SMALL_PRIMES)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Prueba de primalidad probabilistica de Miller-Rabin.

    Primero descarta casos triviales y aplica division de prueba por
    SMALL_PRIMES; despues ejecuta 'rounds' rondas de Miller-Rabin con bases
    aleatorias. La probabilidad de aceptar un compuesto es como mucho 4^-rounds.

    :param n: entero a probar.
    :param rounds: numero de rondas de Miller-Rabin.
    :return: False si n es compuesto con certeza; True si es probablemente primo.
    """
    # Casos base.
    if n < 2:
        return False
    if n in _SMALL_PRIMES_SET:
        return True
    if n % 2 == 0:
        return False

    # Division de prueba: descarta rapido la mayoria de compuestos.
    for p in SMALL_PRIMES:
        if n % p == 0:
            return False

    # Paso 1: escribir n - 1 = 2^s * d con d impar.
    # Se divide n - 1 entre 2 mientras sea par, contando las divisiones en s.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        # Paso 2: elegir una base aleatoria a en [2, n - 2].
        # randbelow(n - 3) da [0, n - 4]; sumando 2 queda [2, n - 2].
        a = 2 + secrets.randbelow(n - 3)

        # Paso 3: calcular x = a^d mod n.
        x = modexp(a, d, n)

        # Paso 4: si x es 1 o n - 1, esta base no prueba que n sea compuesto
        # (a es "mentiroso" o n es primo); pasamos a la siguiente ronda.
        if x == 1 or x == n - 1:
            continue

        # Paso 5: elevar x al cuadrado hasta s - 1 veces buscando n - 1.
        # Esto recorre a^(2d), a^(4d), ..., a^(2^(s-1) d) mod n.
        for _ in range(s - 1):
            x = modexp(x, 2, n)
            if x == n - 1:
                break
        else:
            # Paso 6: nunca aparecio n - 1, por lo que a es un testigo de
            # que n es compuesto (en un primo, la secuencia debe llegar a -1
            # antes de llegar a 1, salvo que empiece en 1).
            return False

    # Paso 7: n supero todas las rondas; es primo con altisima probabilidad.
    return True


def generate_prime(bits: int) -> int:
    """
    Genera un primo probable de exactamente 'bits' bits.

    :param bits: longitud en bits del primo (>= 2).
    :return: entero primo probable con bit_length() == bits.
    :raises ValueError: si bits < 2.
    """
    if bits < 2:
        raise ValueError("bits debe ser al menos 2")

    while True:
        candidato = secrets.randbits(bits)
        # Forzamos los DOS bits mas altos: el primo tiene exactamente 'bits'
        # bits y es >= 1.5 * 2^(bits-1). Asi el producto de dos primos de
        # b/2 bits siempre tiene exactamente b bits (sin reintentos en keygen).
        candidato |= 0b11 << (bits - 2)
        # Forzamos el bit menos significativo para que sea impar.
        candidato |= 1
        if is_probable_prime(candidato):
            return candidato
