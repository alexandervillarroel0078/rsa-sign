"""Pruebas para generacion de claves RSA, cifrado basico y persistencia (src/rsa.py)."""

import os
import tempfile
import unittest

from src.rsa import (
    generate_keypair,
    rsa_encrypt_int,
    rsa_decrypt_int,
    save_public_key,
    load_public_key,
    save_private_key,
    load_private_key,
    RSAPublicKey,
    RSAPrivateKey,
)


class TestRSA(unittest.TestCase):
    """Pruebas de generacion de claves y operaciones basicas RSA."""

    def test_generacion_claves_128_bits(self):
        """Generacion de claves de 128 bits: p, q, n, e, d son correctos."""
        pub, priv = generate_keypair(bits=128)
        self.assertEqual(pub.bit_length(), 128)
        self.assertEqual(priv.bit_length(), 128)
        self.assertEqual(pub.n, priv.n)
        self.assertEqual(pub.e, priv.e)
        self.assertEqual(priv.p * priv.q, priv.n)

        # Verificar relacion ed = 1 mod phi(n)
        phi = (priv.p - 1) * (priv.q - 1)
        self.assertEqual((priv.e * priv.d) % phi, 1)

    def test_cifrado_descifrado_enteros(self):
        """Cifrado y descifrado de enteros m^e mod n y c^d mod n."""
        pub, priv = generate_keypair(bits=128)
        m = 123456789
        c = rsa_encrypt_int(m, pub)
        self.assertNotEqual(m, c)
        dec = rsa_decrypt_int(c, priv)
        self.assertEqual(m, dec)

    def test_guardado_y_carga_claves_pem(self):
        """Persistencia de clave publica y privada en formato legible."""
        pub, priv = generate_keypair(bits=128)

        with tempfile.TemporaryDirectory() as tmpdir:
            pub_path = os.path.join(tmpdir, "public.pem")
            priv_path = os.path.join(tmpdir, "private.pem")

            save_public_key(pub, pub_path)
            save_private_key(priv, priv_path)

            loaded_pub = load_public_key(pub_path)
            loaded_priv = load_private_key(priv_path)

            self.assertEqual(pub.n, loaded_pub.n)
            self.assertEqual(pub.e, loaded_pub.e)
            self.assertEqual(priv.n, loaded_priv.n)
            self.assertEqual(priv.d, loaded_priv.d)
            self.assertEqual(priv.p, loaded_priv.p)
            self.assertEqual(priv.q, loaded_priv.q)


if __name__ == "__main__":
    unittest.main()
