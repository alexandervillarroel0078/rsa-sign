"""Pruebas del esquema de firma RSA-PSS y verificacion en tiempo constante (src/pss.py)."""

import unittest

from src.pss import (
    constant_time_compare,
    emsa_pss_encode,
    emsa_pss_verify,
    rsa_sign_pss,
    rsa_verify_pss,
)
from src.rsa import generate_keypair


class TestPSS(unittest.TestCase):
    """Pruebas para el relleno PSS y comparacion en tiempo constante."""

    def test_constant_time_compare(self):
        """Comparacion en tiempo constante para igualdad e inequidad."""
        self.assertTrue(constant_time_compare(b"abc", b"abc"))
        self.assertTrue(constant_time_compare(b"", b""))
        self.assertFalse(constant_time_compare(b"abc", b"abd"))
        self.assertFalse(constant_time_compare(b"abc", b"ab"))
        self.assertFalse(constant_time_compare(b"abc", b"abcd"))

    def test_emsa_pss_encode_y_verify(self):
        """Codificacion EMSA-PSS y verificacion directa del bloque EM."""
        mensaje = b"Documento universitario para firma electronica."
        em_bits = 1023  # correspondiente a un modulo de 1024 bits

        em = emsa_pss_encode(mensaje, em_bits)
        self.assertTrue(emsa_pss_verify(mensaje, em, em_bits))

        # Mensaje modificado debe fallar la verificacion
        self.assertFalse(emsa_pss_verify(b"Documento adulterado", em, em_bits))

    def test_firma_y_verificacion_extremo_a_extremo(self):
        """Generacion de firma con clave privada y verificacion con clave publica."""
        pub, priv = generate_keypair(bits=1024)
        mensaje = b"Aprobado con nota maxima en Criptografia."

        firma = rsa_sign_pss(mensaje, priv)
        self.assertEqual(len(firma), pub.byte_length())

        # Verificacion correcta
        es_valida = rsa_verify_pss(mensaje, firma, pub)
        self.assertTrue(es_valida)

        # Verificacion con otro mensaje debe ser False
        es_valida_falsa = rsa_verify_pss(b"Otro mensaje distinto", firma, pub)
        self.assertFalse(es_valida_falsa)

        # Verificacion con otra clave publica debe ser False
        otra_pub, _ = generate_keypair(bits=1024)
        self.assertFalse(rsa_verify_pss(mensaje, firma, otra_pub))


if __name__ == "__main__":
    unittest.main()
