"""
Generacion de pares de claves RSA (publica y privada).

Implementacion pura en Python sin librerias criptograficas externas.
Utiliza modinv y gcd de mathcore y generate_prime de primes.
"""

import sys
from pathlib import Path

# Soporte para ejecucion tanto como modulo (python -m src.rsa)
# como ejecucion directa como script (python src/rsa.py).
try:
    from .mathcore import gcd, modinv
    from .primes import generate_prime
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.mathcore import gcd, modinv
    from src.primes import generate_prime


# Exponente publico estandar de Fermat F4 = 2^16 + 1
E_DEFAULT: int = 65537


def generate_keypair(bits: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Genera un par de claves RSA (publica y privada) con un modulo de la longitud dada.

    :param bits: Longitud total en bits del modulo n (entero par >= 512).
    :return: Tupla ((n, e), (n, d)) correspondiente a (clave_publica, clave_privada).
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

            # Exponente privado d tal que (e * d) = 1 (mod phi)
            d = modinv(e, phi)
            encontrado = True
            break

        if encontrado:
            break

    # Clave publica: (n, e)
    public_key = (n, e)
    # Clave privada: (n, d)
    private_key = (n, d)

    return (public_key, private_key)


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
