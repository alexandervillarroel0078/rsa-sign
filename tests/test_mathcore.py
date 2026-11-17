"""Pruebas del nucleo aritmetico (src/mathcore.py)."""

import secrets
import unittest

from src.mathcore import egcd, gcd, modexp, modinv


def _rand_int(max_bits: int) -> int:
    """Entero aleatorio no negativo con hasta 'max_bits' bits (usa secrets)."""
    bits = 1 + secrets.randbelow(max_bits)
    return secrets.randbits(bits)


class TestEgcd(unittest.TestCase):
    """Algoritmo de Euclides extendido."""

    def test_identidad_bezout_1000_pares(self):
        """a*x + b*y == g y g coincide con gcd en 1000 pares aleatorios."""
        for _ in range(1000):
            a = _rand_int(512)
            b = _rand_int(512)
            g, x, y = egcd(a, b)
            with self.subTest(a=a, b=b):
                self.assertEqual(a * x + b * y, g)
                self.assertEqual(g, gcd(a, b))


class TestModinv(unittest.TestCase):
    """Inverso modular."""

    def test_caso_conocido(self):
        """3 * 4 = 12 = 1 (mod 11)."""
        self.assertEqual(modinv(3, 11), 4)

    def test_error_si_no_coprimos(self):
        """Debe lanzar ValueError si gcd(a, n) != 1."""
        with self.assertRaises(ValueError):
            modinv(6, 9)
        with self.assertRaises(ValueError):
            modinv(0, 7)


class TestModexp(unittest.TestCase):
    """Exponenciacion modular."""

    def test_contra_pow_1000_casos(self):
        """Comparacion contra pow(a, b, n) con numeros de hasta 2048 bits."""
        for _ in range(1000):
            a = _rand_int(2048)
            b = _rand_int(2048)
            n = _rand_int(2048) + 1  # modulo >= 1
            with self.subTest(a=a, b=b, n=n):
                self.assertEqual(modexp(a, b, n), pow(a, b, n))


if __name__ == "__main__":
    unittest.main()
