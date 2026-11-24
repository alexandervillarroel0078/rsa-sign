"""Pruebas unitarias para generacion de claves, cifrado, descifrado y serializacion RSA (src/rsa.py)."""

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from src.mathcore import gcd, modexp
from src.rsa import (
    E_DEFAULT,
    bytes_to_int,
    decrypt,
    encrypt,
    generate_keypair,
    int_to_bytes,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


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


class TestRSACipher(unittest.TestCase):
    """Pruebas unitarias para cifrado, descifrado y persistencia de claves RSA."""

    def test_roundtrip_512(self):
        """Generar clave 512, cifrar y descifrar 5 mensajes de longitudes variables (1 a ~50 bytes)."""
        pub, priv = generate_keypair(512)
        n, _ = pub
        longitudes = [1, 10, 25, 40, 50]
        for l in longitudes:
            with self.subTest(longitud=l):
                primer_byte = bytes([secrets.randbelow(255) + 1])
                resto = secrets.token_bytes(l - 1) if l > 1 else b""
                m = primer_byte + resto
                self.assertLess(len(m), (n.bit_length() // 8) - 1)
                ct = encrypt(m, pub, allow_weak=True)
                self.assertEqual(len(ct), (n.bit_length() + 7) // 8)
                recuperado = decrypt(ct, priv)
                self.assertEqual(recuperado, m)

    def test_roundtrip_1024(self):
        """Generar clave 1024, cifrar y descifrar 5 mensajes de longitudes variables."""
        pub, priv = generate_keypair(1024)
        n, _ = pub
        longitudes = [1, 15, 45, 80, 110]
        for l in longitudes:
            with self.subTest(longitud=l):
                primer_byte = bytes([secrets.randbelow(255) + 1])
                resto = secrets.token_bytes(l - 1) if l > 1 else b""
                m = primer_byte + resto
                self.assertLess(len(m), (n.bit_length() // 8) - 1)
                ct = encrypt(m, pub, allow_weak=True)
                self.assertEqual(len(ct), (n.bit_length() + 7) // 8)
                recuperado = decrypt(ct, priv)
                self.assertEqual(recuperado, m)

    def test_mensaje_vacio(self):
        """encrypt(b"") y decrypt(...) devuelven b""."""
        pub, priv = generate_keypair(512)
        ct = encrypt(b"", pub, allow_weak=True)
        recuperado = decrypt(ct, priv)
        self.assertEqual(recuperado, b"")

    def test_mensaje_demasiado_largo(self):
        """Mensaje >= n.bit_length() // 8 bytes lanza ValueError."""
        pub, _ = generate_keypair(512)
        n, _ = pub
        limite_bytes = n.bit_length() // 8
        for l in (limite_bytes, limite_bytes + 1, limite_bytes + 20):
            with self.subTest(longitud=l):
                msg = b"A" * l
                with self.assertRaises(ValueError):
                    encrypt(msg, pub, allow_weak=True)

    def test_guardar_cargar_publica(self):
        """save -> load devuelve los mismos (n, e). Usa NamedTemporaryFile y TemporaryDirectory."""
        pub, _ = generate_keypair(512)

        # 1. Uso con TemporaryDirectory
        with tempfile.TemporaryDirectory() as tmpdir:
            p_dir = Path(tmpdir) / "public_key.json"
            save_public_key(pub, p_dir)
            cargada = load_public_key(p_dir, allow_weak=True)
            self.assertEqual(cargada, pub)

        # 2. Uso con NamedTemporaryFile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmpfile:
            p_file = Path(tmpfile.name)
        try:
            save_public_key(pub, p_file)
            cargada = load_public_key(p_file, allow_weak=True)
            self.assertEqual(cargada, pub)
        finally:
            if p_file.exists():
                p_file.unlink()

    def test_guardar_cargar_privada(self):
        """save -> load devuelve los mismos (n, d). Usa NamedTemporaryFile y TemporaryDirectory."""
        _, priv = generate_keypair(512)

        # 1. Uso con TemporaryDirectory
        with tempfile.TemporaryDirectory() as tmpdir:
            p_dir = Path(tmpdir) / "private_key.json"
            save_private_key(priv, p_dir)
            cargada = load_private_key(p_dir)
            self.assertEqual(cargada, priv)

        # 2. Uso con NamedTemporaryFile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmpfile:
            p_file = Path(tmpfile.name)
        try:
            save_private_key(priv, p_file)
            cargada = load_private_key(p_file)
            self.assertEqual(cargada, priv)
        finally:
            if p_file.exists():
                p_file.unlink()

    def test_load_archivo_corrupto(self):
        """JSON invalido, contenido no diccionario o campos faltantes lanzan ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Archivo con sintaxis JSON corrupta
            p_sintaxis = Path(tmpdir) / "corrupto.json"
            p_sintaxis.write_text("{ esto no es un json valido }", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(p_sintaxis)
            with self.assertRaises(ValueError):
                load_private_key(p_sintaxis)

            # Archivo con JSON que no es un objeto
            p_lista = Path(tmpdir) / "lista.json"
            p_lista.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(p_lista)
            with self.assertRaises(ValueError):
                load_private_key(p_lista)

            # Archivo con campos faltantes
            p_incompleto = Path(tmpdir) / "incompleto.json"
            p_incompleto.write_text('{"n": "0x1234"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(p_incompleto)
            with self.assertRaises(ValueError):
                load_private_key(p_incompleto)

            # Archivo con valores no hexadecimales
            p_no_hex = Path(tmpdir) / "no_hex.json"
            p_no_hex.write_text('{"n": "0xZZZZ", "e": "0x10001"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(p_no_hex)

    def test_load_archivo_inexistente(self):
        """Cargar un archivo inexistente lanza FileNotFoundError."""
        ruta_inexistente = Path("archivo_inexistente_999999.json")
        with self.assertRaises(FileNotFoundError):
            load_public_key(ruta_inexistente)
        with self.assertRaises(FileNotFoundError):
            load_private_key(ruta_inexistente)

    def test_hex_consistente(self):
        """El JSON guardado tiene n, e (o d) como cadenas hexadecimales con prefijo '0x'."""
        pub, priv = generate_keypair(512)
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pub = Path(tmpdir) / "pub.json"
            p_priv = Path(tmpdir) / "priv.json"
            save_public_key(pub, p_pub)
            save_private_key(priv, p_priv)

            with open(p_pub, "r", encoding="utf-8") as f:
                data_pub = json.load(f)
            with open(p_priv, "r", encoding="utf-8") as f:
                data_priv = json.load(f)

            self.assertIn("n", data_pub)
            self.assertIn("e", data_pub)
            self.assertIsInstance(data_pub["n"], str)
            self.assertIsInstance(data_pub["e"], str)
            self.assertTrue(data_pub["n"].startswith("0x"))
            self.assertTrue(data_pub["e"].startswith("0x"))

            self.assertIn("n", data_priv)
            self.assertIn("d", data_priv)
            self.assertIsInstance(data_priv["n"], str)
            self.assertIsInstance(data_priv["d"], str)
            self.assertTrue(data_priv["n"].startswith("0x"))
            self.assertTrue(data_priv["d"].startswith("0x"))

    def test_helpers_bytes_int(self):
        """Pruebas de helpers de conversion bytes_to_int e int_to_bytes."""
        self.assertEqual(bytes_to_int(b""), 0)
        self.assertEqual(bytes_to_int(b"\x00"), 0)
        self.assertEqual(bytes_to_int(b"\x01"), 1)
        self.assertEqual(int_to_bytes(0), b"")
        self.assertEqual(int_to_bytes(0, length=4), b"\x00\x00\x00\x00")
        self.assertEqual(int_to_bytes(1), b"\x01")
        self.assertEqual(int_to_bytes(bytes_to_int(b"Hola")), b"Hola")
        with self.assertRaises(ValueError):
            int_to_bytes(-1)


if __name__ == "__main__":
    unittest.main()
