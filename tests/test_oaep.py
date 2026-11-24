"""Pruebas unitarias para relleno OAEP (src/oaep.py) y cifrado/descifrado RSA-OAEP (src/rsa.py)."""

import hashlib
import unittest

from src.oaep import (
    HLEN,
    mgf1,
    oaep_decode,
    oaep_encode,
)
from src.rsa import (
    decrypt_oaep,
    encrypt_oaep,
    generate_keypair,
)


def _mgf1_hashlib_referencia(seed: bytes, length: int) -> bytes:
    """Implementacion de referencia de MGF1 usando hashlib.sha256 para verificacion en tests."""
    t = bytearray()
    counter = 0
    while len(t) < length:
        c = counter.to_bytes(4, "big")
        t.extend(hashlib.sha256(seed + c).digest())
        counter += 1
    return bytes(t[:length])


class TestOAEP(unittest.TestCase):
    """Pruebas unitarias para las funciones de relleno MGF1 y OAEP."""

    def test_mgf1_longitud_cero(self):
        """mgf1(b"x", 0) == b""."""
        self.assertEqual(mgf1(b"x", 0), b"")
        self.assertEqual(mgf1(b"", 0), b"")

    def test_mgf1_deterministico(self):
        """mgf1(b"seed", 100) == mgf1(b"seed", 100) y len == 100."""
        res1 = mgf1(b"seed", 100)
        res2 = mgf1(b"seed", 100)
        self.assertEqual(res1, res2)
        self.assertEqual(len(res1), 100)

    def test_mgf1_vs_referencia(self):
        """Comparar con implementacion local usando hashlib.sha256 en el test. Vector: mgf1(b"\x00"*32, 64)."""
        seed = b"\x00" * 32
        salida_mgf1 = mgf1(seed, 64)
        salida_ref = _mgf1_hashlib_referencia(seed, 64)
        self.assertEqual(salida_mgf1, salida_ref)

        for l in (1, 16, 32, 33, 63, 65, 128, 250):
            with self.subTest(longitud=l):
                self.assertEqual(mgf1(b"test_seed_123", l), _mgf1_hashlib_referencia(b"test_seed_123", l))

    def test_mgf1_validaciones(self):
        """mgf1 lanza excepciones ante argumentos de tipo o valor invalidos."""
        with self.assertRaises(ValueError):
            mgf1(b"seed", -1)
        with self.assertRaises(TypeError):
            mgf1("no_bytes", 10)  # type: ignore
        with self.assertRaises(TypeError):
            mgf1(b"seed", "10")  # type: ignore
        with self.assertRaises(TypeError):
            mgf1(b"seed", True)  # type: ignore

    def test_oaep_encode_length(self):
        """len(oaep_encode(m, k)) == k para varios k validos (1024 bits -> 128 bytes, 2048 -> 256)."""
        msg = b"mensaje corto"
        for k in (128, 256):
            with self.subTest(k=k):
                em = oaep_encode(msg, k)
                self.assertEqual(len(em), k)

        # Para k = 64 (512 bits), k < 2*HLEN + 2 (66 bytes), debe lanzar ValueError
        with self.assertRaises(ValueError):
            oaep_encode(msg, 64)

    def test_oaep_roundtrip(self):
        """encode/decode con 5 mensajes de longitudes [0, 1, 30, max-1, max] para k de 1024 bits (128 bytes)."""
        k = 128
        max_len = k - 2 * HLEN - 2  # 128 - 66 = 62 bytes
        longitudes = [0, 1, 30, max_len - 1, max_len]

        for l in longitudes:
            with self.subTest(longitud=l):
                msg = b"X" * l
                em = oaep_encode(msg, k)
                self.assertEqual(len(em), k)
                recuperado = oaep_decode(em, k)
                self.assertEqual(recuperado, msg)

        # Con k=64 (512 bits), k < 66 debe fallar con ValueError
        with self.assertRaises(ValueError):
            oaep_encode(b"", 64)

    def test_oaep_mensaje_maximo(self):
        """len(msg) == k - 2*32 - 2 OK; uno mas -> ValueError."""
        k = 128
        max_len = k - 2 * HLEN - 2  # 62 bytes

        msg_max = b"A" * max_len
        em = oaep_encode(msg_max, k)
        self.assertEqual(oaep_decode(em, k), msg_max)

        msg_exceso = b"A" * (max_len + 1)
        with self.assertRaises(ValueError):
            oaep_encode(msg_exceso, k)

    def test_oaep_label_distinto_falla(self):
        """encode con label b"A", decode con label b"B" -> ValueError."""
        k = 128
        msg = b"contenido confidencial"
        em = oaep_encode(msg, k, label=b"A")

        # Con misma etiqueta decodifica correctamente
        self.assertEqual(oaep_decode(em, k, label=b"A"), msg)

        # Con etiqueta distinta debe fallar
        with self.assertRaises(ValueError):
            oaep_decode(em, k, label=b"B")

    def test_oaep_byte_alterado(self):
        """alterar 1 byte en maskedSeed, en maskedDB, en Y -> ValueError."""
        k = 128
        msg = b"integridad del padding"
        em = bytearray(oaep_encode(msg, k))

        # 1. Alterar Y (posicion 0)
        em_y = bytearray(em)
        em_y[0] ^= 0xFF
        with self.assertRaises(ValueError):
            oaep_decode(bytes(em_y), k)

        # 2. Alterar maskedSeed (posiciones 1 a 32)
        for offset in (1, 16, 32):
            em_seed = bytearray(em)
            em_seed[offset] ^= 0x01
            with self.assertRaises(ValueError):
                oaep_decode(bytes(em_seed), k)

        # 3. Alterar maskedDB (posiciones 33 en adelante)
        for offset in (33, 50, 100, 127):
            em_db = bytearray(em)
            em_db[offset] ^= 0x01
            with self.assertRaises(ValueError):
                oaep_decode(bytes(em_db), k)


class TestRSAOAEP(unittest.TestCase):
    """Pruebas de integracion cifrado/descifrado RSA con relleno OAEP."""

    def test_encrypt_decrypt_oaep_512(self):
        """Para 512 bits (k=64 bytes), k < 66 bytes necesarios para OAEP-SHA256, debe lanzar ValueError."""
        pub512, priv512 = generate_keypair(512)
        with self.assertRaises(ValueError):
            encrypt_oaep(b"Hola OAEP", pub512)

    def test_encrypt_decrypt_oaep_1024(self):
        """Round-trip con encrypt_oaep/decrypt_oaep para clave de 1024 bits con multiples mensajes."""
        pub1024, priv1024 = generate_keypair(1024)
        mensajes = [
            b"",
            b"A",
            b"Hola OAEP!",
            b"Mensaje de longitud media con caracteres 1234567890",
            b"Z" * 62,
        ]
        for m in mensajes:
            with self.subTest(msg=m):
                ct = encrypt_oaep(m, pub1024)
                self.assertEqual(len(ct), 128)
                recuperado = decrypt_oaep(ct, priv1024)
                self.assertEqual(recuperado, m)

    def test_encrypt_oaep_aleatorio(self):
        """dos encrypt_oaep(m, pub) del mismo m -> criptogramas distintos (por seed aleatorio)."""
        pub, _ = generate_keypair(1024)
        m = b"mensaje para probar no determinismo"
        ct1 = encrypt_oaep(m, pub)
        ct2 = encrypt_oaep(m, pub)
        self.assertNotEqual(ct1, ct2)
        self.assertEqual(len(ct1), 128)
        self.assertEqual(len(ct2), 128)

    def test_encrypt_oaep_mensaje_largo(self):
        """len(msg) > k - 2*32 - 2 -> ValueError."""
        pub, _ = generate_keypair(1024)
        n, _ = pub
        k = (n.bit_length() + 7) // 8  # 128
        max_len = k - 2 * 32 - 2  # 62

        msg_exceso = b"A" * (max_len + 1)
        with self.assertRaises(ValueError):
            encrypt_oaep(msg_exceso, pub)

    def test_decrypt_oaep_criptograma_invalido(self):
        """decrypt_oaep valida longitud de criptograma y c < n."""
        pub, priv = generate_keypair(1024)
        n, _ = pub

        # Longitud incorrecta
        with self.assertRaises(ValueError):
            decrypt_oaep(b"\x00" * 64, priv)

        # c >= n
        ct_invalido = (n + 1).to_bytes(128, "big")
        with self.assertRaises(ValueError):
            decrypt_oaep(ct_invalido, priv)

    def test_encrypt_decrypt_con_label(self):
        """Cifrado y descifrado con etiquetas coincidentes y discrepantes."""
        pub, priv = generate_keypair(1024)
        m = b"datos con etiqueta"
        ct = encrypt_oaep(m, pub, label=b"autenticacion-ctx")

        # Con misma etiqueta decodifica
        recuperado = decrypt_oaep(ct, priv, label=b"autenticacion-ctx")
        self.assertEqual(recuperado, m)

        # Con etiqueta diferente falla
        with self.assertRaises(ValueError):
            decrypt_oaep(ct, priv, label=b"otro-ctx")
