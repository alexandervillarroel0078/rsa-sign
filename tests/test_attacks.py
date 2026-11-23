"""
Pruebas de ataques criptograficos (src/attacks.py).

Cubre:
1. Pruebas de raiz cuadrada entera e identificacion de cuadrados perfectos.
2. Factorizacion de Fermat en casos pequenos y recuperacion completa de clave RSA.
3. Resistencia del RSA estandar ante el ataque de Fermat.
4. Ataque por alteracion de 1 bit en firma y mensaje (rechazo estricto).
"""

import math
import secrets
import unittest

from src.attacks import (
    corrupt_bit,
    fermat_attack_rsa,
    fermat_factor,
    generate_weak_fermat_key,
    is_square,
    isqrt,
)
from src.oaep import rsa_decrypt_oaep, rsa_encrypt_oaep
from src.pss import rsa_sign_pss, rsa_verify_pss
from src.rsa import generate_keypair


class TestAttacks(unittest.TestCase):
    """Pruebas de los modulos de ataque."""

    def test_isqrt_comparacion_math_isqrt(self):
        """isqrt implementado a mano coincide exactamente con math.isqrt en numeros grandes."""
        # Casos basicos
        self.assertEqual(isqrt(0), 0)
        self.assertEqual(isqrt(1), 1)
        self.assertEqual(isqrt(15), 3)
        self.assertEqual(isqrt(16), 4)
        self.assertEqual(isqrt(17), 4)

        # 50 casos aleatorios de hasta 2048 bits
        for _ in range(50):
            bits = 1 + secrets.randbelow(2048)
            num = secrets.randbits(bits)
            self.assertEqual(isqrt(num), math.isqrt(num))

    def test_is_square(self):
        """Identificacion correcta de cuadrados perfectos y sus raices."""
        self.assertEqual(is_square(0), (True, 0))
        self.assertEqual(is_square(1), (True, 1))
        self.assertEqual(is_square(144), (True, 12))
        self.assertEqual(is_square(143), (False, 11))
        self.assertEqual(is_square(145), (False, 12))

    def test_fermat_factor_casos_pequenos(self):
        """Fermat factoriza semiprimos con factores cercanos en 1 iteracion."""
        # 101 * 103 = 10403
        factores = fermat_factor(10403)
        self.assertEqual(factores, (101, 103))

        # 1009 * 1013 = 1022117
        factores2 = fermat_factor(1022117)
        self.assertEqual(factores2, (1009, 1013))

    def test_fermat_ataque_rsa_recuperacion_clave_y_descifrado(self):
        """
        Demuestra la vulnerabilidad de RSA ante primos cercanos:
        El atacante obtiene (p, q), reconstruye d, y descifra un criptograma OAEP.
        """
        # Generamos una clave debil de 1024 bits (p y q consecutivos)
        pub_debil, priv_original = generate_weak_fermat_key(bits=1024)

        # Ataque de Fermat: solo conoce la clave publica (n, e)
        resultado = fermat_attack_rsa(pub_debil, max_iter=1000)
        self.assertIsNotNone(resultado, "El ataque de Fermat deberia haber tenido exito.")

        priv_atacante, iteraciones = resultado
        # Verifica que recupero la clave privada correcta
        self.assertEqual(priv_atacante.d, priv_original.d)
        self.assertEqual(priv_atacante.p, priv_original.p)
        self.assertEqual(priv_atacante.q, priv_original.q)

        # Ahora el atacante descifra un mensaje que la victima cifro con su clave publica
        mensaje_secreto = b"Clave secreta descubierta por Fermat"
        criptograma = rsa_encrypt_oaep(mensaje_secreto, pub_debil)

        # El atacante usa su d recuperado para descifrar:
        texto_descifrado = rsa_decrypt_oaep(criptograma, priv_atacante)
        self.assertEqual(texto_descifrado, mensaje_secreto)

    def test_fermat_falla_con_primos_seguros(self):
        """
        Demuestra la seguridad de RSA estandar: con primos independientes y lejanos,
        el ataque de Fermat no converge en pocas iteraciones y devuelve None.
        """
        pub_segura, _ = generate_keypair(bits=256)
        # Limitamos a 50 iteraciones: con primos lejanos se necesitarian 2^100+ iteraciones
        resultado = fermat_attack_rsa(pub_segura, max_iter=50)
        self.assertIsNone(resultado)

    def test_ataque_alteracion_un_bit_en_firma(self):
        """
        Demuestra que cambiar un solo bit en la firma PSS invalida la verificacion.
        """
        pub, priv = generate_keypair(bits=1024)
        mensaje = b"Transferir 1000 USD a la cuenta de Josue"
        firma_legitima = rsa_sign_pss(mensaje, priv)

        # La firma original es valida
        self.assertTrue(rsa_verify_pss(mensaje, firma_legitima, pub))

        # El atacante altera el bit 0 de la firma
        firma_adulterada = corrupt_bit(firma_legitima, bit_index=0)
        self.assertNotEqual(firma_legitima, firma_adulterada)
        self.assertFalse(rsa_verify_pss(mensaje, firma_adulterada, pub))

        # El atacante altera el bit en la mitad de la firma
        bit_medio = (len(firma_legitima) * 8) // 2
        firma_adulterada_2 = corrupt_bit(firma_legitima, bit_index=bit_medio)
        self.assertFalse(rsa_verify_pss(mensaje, firma_adulterada_2, pub))

    def test_ataque_alteracion_un_bit_en_mensaje(self):
        """
        Demuestra que si el atacante altera 1 bit en el mensaje firmado, la firma no coincide.
        """
        pub, priv = generate_keypair(bits=1024)
        mensaje = b"Transferir 1000 USD"
        firma = rsa_sign_pss(mensaje, priv)

        # Alteramos 1 bit en el mensaje
        mensaje_alterado = corrupt_bit(mensaje, bit_index=3)
        self.assertNotEqual(mensaje, mensaje_alterado)
        self.assertFalse(rsa_verify_pss(mensaje_alterado, firma, pub))


if __name__ == "__main__":
    unittest.main()
