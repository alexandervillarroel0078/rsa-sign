"""
Pruebas unitarias para el esquema de firma RSA-PSS (EMSA-PSS-SHA256).

Verifica la codificacion y decodificacion EMSA-PSS segun RFC 8017,
la generacion y verificacion de firmas con clave RSA de 1024 bits,
casos de firma alterada, mensaje alterado, longitudes invalidas,
resistencia contra entradas aleatorias y gestion estricta de tipos.
"""

import secrets
import unittest

from src.pss import HLEN_PSS, emsa_pss_encode, emsa_pss_verify
from src.rsa import generate_keypair, sign, verify
from src.sha256 import sha256


class TestEMSAPSS(unittest.TestCase):
    """Pruebas de codificacion y verificacion EMSA-PSS con SHA-256."""

    def test_emsa_pss_roundtrip(self):
        """encode/decode con 5 mensajes, em_bits en {511, 1023, 1024}, salt_len adaptativo/32 -> True."""
        mensajes = [
            b"",
            b"a",
            b"Hola EMSA-PSS",
            b"Mensaje de prueba de longitud media para el esquema de firma probabilistica",
            bytes(range(256)),
        ]
        bits_list = [511, 1023, 1024]
        for msg in mensajes:
            m_hash = sha256(msg)
            for em_bits in bits_list:
                # Con em_bits=511, em_len=64 bytes < 66 requeridos para salt_len=32 (HLEN 32 + salt 32 + 2 = 66),
                # por lo que se ajusta salt_len al maximo admisible (30 bytes) segun RFC 8017.
                em_len = (em_bits + 7) // 8
                salt_len = 32 if em_len >= HLEN_PSS + 32 + 2 else (em_len - HLEN_PSS - 2)
                with self.subTest(msg=msg[:10], em_bits=em_bits):
                    em = emsa_pss_encode(m_hash, em_bits, salt_len=salt_len)
                    es_valido = emsa_pss_verify(m_hash, em, em_bits, salt_len=salt_len)
                    self.assertTrue(es_valido)

    def test_emsa_pss_em_length(self):
        """len(em) == (em_bits + 7) // 8 para varios tamanos de bits."""
        m_hash = sha256(b"Prueba de longitud")
        bits_a_probar = [528, 529, 1023, 1024, 2047, 2048]
        for em_bits in bits_a_probar:
            with self.subTest(em_bits=em_bits):
                em = emsa_pss_encode(m_hash, em_bits, salt_len=32)
                expected_len = (em_bits + 7) // 8
                self.assertEqual(len(em), expected_len)

    def test_emsa_pss_modulo_pequeno(self):
        """em_len < HLEN + salt_len + 2 -> ValueError en encode; False en verify."""
        m_hash = sha256(b"Modulo pequeno")
        salt_len = 32
        # Minimo requerimiento: HLEN + salt_len + 2 = 32 + 32 + 2 = 66 bytes = 528 bits
        # Con em_bits = 500, em_len = (500 + 7) // 8 = 63 < 66
        em_bits_pequeno = 500
        with self.assertRaises(ValueError):
            emsa_pss_encode(m_hash, em_bits_pequeno, salt_len=salt_len)

        # verify con em_bits pequeno debe retornar False sin lanzar excepcion
        em_dummy = b"\x00" * ((em_bits_pequeno + 7) // 8)
        self.assertFalse(emsa_pss_verify(m_hash, em_dummy, em_bits_pequeno, salt_len=salt_len))

    def test_emsa_pss_trailer_invalido(self):
        """cambiar em[-1] -> verify False."""
        m_hash = sha256(b"Trailer test")
        em_bits = 1024
        em = emsa_pss_encode(m_hash, em_bits, salt_len=32)
        # Cambiar el ultimo byte (debe ser 0xbc)
        em_invalido = em[:-1] + bytes([em[-1] ^ 0x01])
        self.assertFalse(emsa_pss_verify(m_hash, em_invalido, em_bits, salt_len=32))

    def test_emsa_pss_bits_altos_nonzero(self):
        """poner bits altos en masked_db[0] -> verify False."""
        m_hash = sha256(b"Bits altos test")
        # em_bits = 1023 -> em_len = 128 bytes (1024 bits). El bit mas significativo debe ser 0.
        em_bits = 1023
        em = emsa_pss_encode(m_hash, em_bits, salt_len=32)
        # Forzar el bit superior a 1
        em_corrupto = bytes([em[0] | 0x80]) + em[1:]
        self.assertFalse(emsa_pss_verify(m_hash, em_corrupto, em_bits, salt_len=32))

    def test_emsa_pss_byte_alterado(self):
        """alterar 1 byte en masked_db, en H, en salt -> verify False."""
        m_hash = sha256(b"Byte alterado test")
        em_bits = 1024
        salt_len = 32
        em = bytearray(emsa_pss_encode(m_hash, em_bits, salt_len=salt_len))
        em_len = len(em)
        db_len = em_len - HLEN_PSS - 1

        # 1. Alterar 1 byte en masked_db (zona de relleno PS)
        em_ps = bytearray(em)
        em_ps[1] ^= 0x01
        self.assertFalse(emsa_pss_verify(m_hash, bytes(em_ps), em_bits, salt_len=salt_len))

        # 2. Alterar 1 byte en masked_db (zona del salt dentro de DB)
        em_salt = bytearray(em)
        em_salt[db_len - 2] ^= 0x01
        self.assertFalse(emsa_pss_verify(m_hash, bytes(em_salt), em_bits, salt_len=salt_len))

        # 3. Alterar 1 byte en H (entre db_len y em_len - 1)
        em_h = bytearray(em)
        em_h[db_len + 5] ^= 0x01
        self.assertFalse(emsa_pss_verify(m_hash, bytes(em_h), em_bits, salt_len=salt_len))

    def test_emsa_pss_no_deterministico(self):
        """dos emsa_pss_encode del mismo m_hash -> distintos (por salt aleatorio)."""
        m_hash = sha256(b"Mismo hash")
        em_bits = 1024
        em1 = emsa_pss_encode(m_hash, em_bits, salt_len=32)
        em2 = emsa_pss_encode(m_hash, em_bits, salt_len=32)
        self.assertNotEqual(em1, em2)


class TestRSAPSS(unittest.TestCase):
    """Pruebas de integracion de firma y verificacion RSA-PSS."""

    @classmethod
    def setUpClass(cls):
        # Generar un par de claves de 1024 bits una sola vez para la clase
        cls.pub1024, cls.priv1024 = generate_keypair(1024)

    def test_sign_verify_1024(self):
        """sign(msg, priv) y verify(msg, sig, pub) -> True para 5 mensajes."""
        mensajes = [
            b"",
            b"Documento confidencial",
            b"Transaccion bancaria #984712",
            b"Texto largo para probar firma digital con algoritmo RSA-PSS y funcion de hash SHA-256.",
            bytes([i % 256 for i in range(500)]),
        ]
        for msg in mensajes:
            with self.subTest(msg=msg[:15]):
                sig = sign(msg, self.priv1024)
                self.assertTrue(verify(msg, sig, self.pub1024))

    @unittest.skip("2048 bits omitido por tiempo de ejecucion en suite normal")
    def test_sign_verify_2048_skip(self):
        """Firma y verificacion con clave de 2048 bits (skip por rendimiento)."""
        pub2048, priv2048 = generate_keypair(2048)
        msg = b"Mensaje para clave de 2048 bits"
        sig = sign(msg, priv2048)
        self.assertTrue(verify(msg, sig, pub2048))

    def test_verify_firma_alterada_1bit(self):
        """alterar 1 bit de sig -> verify False."""
        msg = b"Mensaje integro"
        sig = bytearray(sign(msg, self.priv1024))
        # Alterar el bit menos significativo del primer byte
        sig[0] ^= 0x01
        self.assertFalse(verify(msg, bytes(sig), self.pub1024))

    def test_verify_mensaje_distinto(self):
        """firmar A, verificar B -> False."""
        msg_a = b"Transferir $100"
        msg_b = b"Transferir $1000"
        sig = sign(msg_a, self.priv1024)
        self.assertFalse(verify(msg_b, sig, self.pub1024))

    def test_verify_longitud_invalida(self):
        """sig de longitud != k -> False (no excepcion)."""
        msg = b"Prueba de longitud incorrecta"
        sig = sign(msg, self.priv1024)
        n, _ = self.pub1024
        k = (n.bit_length() + 7) // 8

        self.assertEqual(len(sig), k)
        # Longitudes incorrectas
        self.assertFalse(verify(msg, sig + b"\x00", self.pub1024))
        self.assertFalse(verify(msg, sig[:-1], self.pub1024))
        self.assertFalse(verify(msg, b"", self.pub1024))

    def test_verify_s_ge_n(self):
        """sig = (n+1).to_bytes(k, "big") -> False."""
        msg = b"Prueba s >= n"
        n, _ = self.pub1024
        k = (n.bit_length() + 7) // 8
        sig_invalida = (n + 1).to_bytes(k, "big")
        self.assertFalse(verify(msg, sig_invalida, self.pub1024))

    def test_verify_firma_aleatoria(self):
        """sig = secrets.token_bytes(k) -> False (probabilistico, con reintentos)."""
        msg = b"Prueba de firma aleatoria"
        n, _ = self.pub1024
        k = (n.bit_length() + 7) // 8

        for _ in range(3):
            sig_aleatoria = secrets.token_bytes(k)
            # Asegurarse de que s < n para que la verificacion procese el bloque PSS
            s = int.from_bytes(sig_aleatoria, "big")
            if s >= n:
                sig_aleatoria = (s % n).to_bytes(k, "big")
            self.assertFalse(verify(msg, sig_aleatoria, self.pub1024))

    def test_verify_tipo_invalido(self):
        """verify("no_bytes", sig, pub) -> TypeError."""
        msg = b"Mensaje para validar tipos"
        sig = sign(msg, self.priv1024)

        with self.assertRaises(TypeError):
            verify("no_bytes", sig, self.pub1024)

        with self.assertRaises(TypeError):
            verify(msg, "no_bytes", self.pub1024)

        with self.assertRaises(TypeError):
            verify(msg, sig, "no_tupla")

        with self.assertRaises(TypeError):
            verify(msg, sig, ("n_no_int", 65537))

    def test_sign_no_deterministico(self):
        """Dos firmas del mismo mensaje deben ser distintas (aleatoriedad del salt PSS)."""
        msg = b"Mismo mensaje a firmar"
        sig1 = sign(msg, self.priv1024)
        sig2 = sign(msg, self.priv1024)
        self.assertNotEqual(sig1, sig2)
        self.assertTrue(verify(msg, sig1, self.pub1024))
        self.assertTrue(verify(msg, sig2, self.pub1024))


if __name__ == "__main__":
    unittest.main()
