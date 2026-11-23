"""Pruebas del relleno OAEP y MGF1 (src/oaep.py y src/mgf1.py)."""

import unittest

from src.mgf1 import mgf1, xor_bytes
from src.oaep import oaep_encode, oaep_decode, rsa_encrypt_oaep, rsa_decrypt_oaep
from src.rsa import generate_keypair


class TestOAEP(unittest.TestCase):
    """Pruebas para mascara MGF1 y relleno OAEP."""

    def test_mgf1_longitud_y_determinismo(self):
        """MGF1 genera mascara de la longitud pedida y es determinista."""
        seed = b"semilla-de-prueba-para-mgf1"
        mask1 = mgf1(seed, 64)
        mask2 = mgf1(seed, 64)
        self.assertEqual(len(mask1), 64)
        self.assertEqual(mask1, mask2)

        # Distinta longitud
        mask_corta = mgf1(seed, 10)
        self.assertEqual(len(mask_corta), 10)
        self.assertEqual(mask_corta, mask1[:10])

    def test_xor_bytes(self):
        """Operacion XOR byte a byte."""
        a = b"\xaa\x55\xff\x00"
        b_bytes = b"\x55\xaa\x00\xff"
        res = xor_bytes(a, b_bytes)
        self.assertEqual(res, b"\xff\xff\xff\xff")
        self.assertEqual(xor_bytes(res, b_bytes), a)

    def test_oaep_encode_decode(self):
        """Codificacion y decodificacion de relleno OAEP."""
        mensaje = b"Criptografia y Seguridad - ELC107"
        em_len = 128  # 1024 bits = 128 bytes

        em = oaep_encode(mensaje, em_len)
        self.assertEqual(len(em), em_len)

        recuperado = oaep_decode(em)
        self.assertEqual(recuperado, mensaje)

    def test_oaep_con_label(self):
        """OAEP con etiqueta personalizada."""
        mensaje = b"Mensaje confidencial"
        label = b"contexto-departamental"
        em_len = 128

        em = oaep_encode(mensaje, em_len, label=label)
        recuperado = oaep_decode(em, label=label)
        self.assertEqual(recuperado, mensaje)

        # Decodificar con etiqueta incorrecta debe fallar
        with self.assertRaises(ValueError):
            oaep_decode(em, label=b"etiqueta-incorrecta")

    def test_oaep_mensaje_demasiado_largo(self):
        """oaep_encode lanza ValueError si el mensaje supera la capacidad."""
        em_len = 128  # Capacidad maxima = 128 - 2*32 - 2 = 62 bytes
        mensaje_grande = b"A" * 63
        with self.assertRaises(ValueError):
            oaep_encode(mensaje_grande, em_len)

    def test_cifrado_descifrado_completo_oaep(self):
        """Cifrado y descifrado de extremo a extremo con RSA-OAEP."""
        pub, priv = generate_keypair(bits=1024)
        mensaje = b"Hola Mundo RSA con OAEP"

        criptograma = rsa_encrypt_oaep(mensaje, pub)
        self.assertEqual(len(criptograma), pub.byte_length())
        self.assertNotEqual(criptograma, mensaje)

        plano = rsa_decrypt_oaep(criptograma, priv)
        self.assertEqual(plano, mensaje)


if __name__ == "__main__":
    unittest.main()
