"""Pruebas de primalidad y generacion de primos (src/primes.py)."""

import unittest

from src.primes import generate_prime, is_probable_prime


def _es_primo_fuerza_bruta(n: int) -> bool:
    """Division de prueba simple, usada como referencia."""
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


class TestIsProbablePrime(unittest.TestCase):
    """Prueba de primalidad Miller-Rabin."""

    def test_primos_conocidos(self):
        """Primos pequenos y primos de Mersenne."""
        for p in (2, 3, 97, 7919, 2**61 - 1, 2**127 - 1):
            with self.subTest(p=p):
                self.assertTrue(is_probable_prime(p))

    def test_compuestos_y_carmichael(self):
        """Compuestos simples y numeros de Carmichael."""
        for n in (0, 1, 4, 100, 561, 1105, 1729, 2465, 2821, 6601, 8911):
            with self.subTest(n=n):
                self.assertFalse(is_probable_prime(n))

    def test_producto_de_primos_grandes(self):
        """El producto de dos primos de Mersenne grandes es compuesto."""
        n = (2**89 - 1) * (2**107 - 1)
        self.assertFalse(is_probable_prime(n))

    def test_concordancia_fuerza_bruta(self):
        """Para todo n < 5000 coincide con division de prueba."""
        for n in range(5000):
            with self.subTest(n=n):
                self.assertEqual(is_probable_prime(n), _es_primo_fuerza_bruta(n))


class TestGeneratePrime(unittest.TestCase):
    """Generacion de primos aleatorios."""

    def test_tamanos(self):
        """64, 256 y 512 bits: longitud exacta, impar y primo."""
        for bits in (64, 256, 512):
            p = generate_prime(bits)
            with self.subTest(bits=bits):
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p % 2, 1)
                self.assertTrue(is_probable_prime(p))

    def test_bits_invalidos(self):
        """generate_prime(1) lanza ValueError."""
        with self.assertRaises(ValueError):
            generate_prime(1)


if __name__ == "__main__":
    unittest.main()
