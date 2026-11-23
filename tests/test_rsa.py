"""Pruebas unitarias para generacion de claves RSA (src/rsa.py)."""

import secrets
import unittest

from src.mathcore import gcd, modexp
from src.rsa import E_DEFAULT, generate_keypair


class TestRSAKeygen(unittest.TestCase):
    """Pruebas unitarias para generate_keypair."""

    def test_tipos_y_tamanos(self):
        """bits=512 y bits=1024 devuelven tuplas validas, longitud exacta, e == 65537 y d > 0."""
        for bits in (512, 1024):
            with self.subTest(bits=bits):
                pub, priv = generate_keypair(bits)
                self.assertIsInstance(pub, tuple)
                self.assertIsInstance(priv, tuple)
                self.assertEqual(len(pub), 2)
                self.assertEqual(len(priv), 2)

                n_pub, e = pub
                n_priv, d = priv

                self.assertEqual(n_pub, n_priv)
                self.assertEqual(e, E_DEFAULT)
                self.assertEqual(e, 65537)
                self.assertGreater(d, 0)
                self.assertEqual(n_pub.bit_length(), bits)

    def test_relacion_matematica(self):
        """Verifica la relacion cifrado/descifrado: modexp(modexp(m, e, n), d, n) == m para 5 mensajes."""
        pub, priv = generate_keypair(512)
        n, e = pub
        _, d = priv

        for _ in range(5):
            # Mensaje m aleatorio en [2, n - 2]
            m = 2 + secrets.randbelow(n - 3)
            self.assertEqual(gcd(m, n), 1)

            c = modexp(m, e, n)
            m_recuperado = modexp(c, d, n)
            self.assertEqual(m_recuperado, m)

    def test_gcd_con_phi(self):
        """Verificacion indirecta de que gcd(e, phi) == 1 mediante round-trip RSA."""
        pub, priv = generate_keypair(512)
        n, e = pub
        _, d = priv

        for _ in range(5):
            m = 2 + secrets.randbelow(n - 3)
            self.assertEqual(modexp(modexp(m, e, n), d, n), m)

    def test_bits_invalidos(self):
        """bits < 512, bits impares o tipos invalidos lanzan ValueError."""
        casos_invalidos = (256, 511, 0, -1, "1024", 512.0, False)
        for val in casos_invalidos:
            with self.subTest(val=val):
                with self.assertRaises(ValueError):
                    generate_keypair(val)

    def test_p_distinto_q(self):
        """En 5 ejecuciones de 512 bits se obtienen modulos n distintos (no colision trivial)."""
        modulos = set()
        for _ in range(5):
            pub, _ = generate_keypair(512)
            n, _ = pub
            self.assertNotIn(n, modulos)
            modulos.add(n)

    def test_dos_claves_independientes(self):
        """Dos llamadas consecutivas producen claves independientes."""
        pub1, priv1 = generate_keypair(512)
        pub2, priv2 = generate_keypair(512)

        self.assertNotEqual(pub1[0], pub2[0])
        self.assertNotEqual(priv1[1], priv2[1])

    @unittest.skip("2048 bits omitido por tiempo de ejecucion en suite normal")
    def test_2048_bits(self):
        """Clave de 2048 bits opcional."""
        pub, priv = generate_keypair(2048)
        self.assertEqual(pub[0].bit_length(), 2048)


if __name__ == "__main__":
    unittest.main()
