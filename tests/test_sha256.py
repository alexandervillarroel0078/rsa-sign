"""Pruebas de la implementacion propia de SHA-256 (src/sha256.py)."""

import hashlib  # Permitido solo en tests, como referencia.
import secrets
import unittest

from src.sha256 import sha256, sha256_hex


class TestSHA256(unittest.TestCase):
    """Vectores NIST y comparacion contra hashlib."""

    def test_vector_vacio(self):
        """Mensaje vacio."""
        self.assertEqual(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_vector_abc(self):
        """Mensaje 'abc' (un solo bloque)."""
        self.assertEqual(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_vector_448_bits(self):
        """Mensaje de 56 bytes (dos bloques tras el relleno)."""
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(
            sha256_hex(msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        )

    def test_vector_millon_a(self):
        """Un millon de caracteres 'a'."""
        self.assertEqual(
            sha256_hex(b"a" * 1_000_000),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        )

    def test_salida_32_bytes(self):
        """sha256 devuelve exactamente 32 bytes."""
        self.assertEqual(len(sha256(b"x")), 32)

    def test_limites_de_bloque(self):
        """Longitudes en los bordes del relleno (55, 56, 63, 64, 65)."""
        for n in (55, 56, 63, 64, 65):
            data = secrets.token_bytes(n)
            with self.subTest(longitud=n):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_aleatorio_contra_hashlib(self):
        """200 entradas aleatorias de longitud 0 a 300 bytes."""
        for _ in range(200):
            n = secrets.randbelow(301)
            data = secrets.token_bytes(n)
            with self.subTest(longitud=n):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())


if __name__ == "__main__":
    unittest.main()
