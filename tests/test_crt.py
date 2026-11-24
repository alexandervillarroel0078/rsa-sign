"""
Pruebas de la Etapa 2: CRT (Garner), blinding, proteccion contra fallos al firmar
y formato de clave privada v2 con carga retrocompatible.
"""

import json
import secrets
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

from src import rsa as rsa_mod
from src.rsa import (
    LegacyKeyFormatWarning,
    RSAPrivateKey,
    decrypt,
    decrypt_oaep,
    encrypt,
    encrypt_oaep,
    generate_keypair,
    load_private_key,
    private_key_from_dict,
    private_key_to_dict,
    rsa_private_op,
    save_private_key,
    sign,
    verify,
)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claves = {bits: generate_keypair(bits) for bits in (1024, 2048)}


class TestCRT(_Base):

    def test_parametros_crt(self):
        for bits, (pub, priv) in self.claves.items():
            with self.subTest(bits=bits):
                self.assertIsInstance(priv, RSAPrivateKey)
                self.assertTrue(priv.has_crt)
                n, d = priv
                p, q = priv.p, priv.q
                self.assertEqual(p * q, n)
                self.assertEqual(priv.e, pub[1])
                self.assertEqual(priv.dp, d % (p - 1))
                self.assertEqual(priv.dq, d % (q - 1))
                self.assertEqual((priv.qinv * q) % p, 1)
                self.assertEqual((priv.e * d) % ((p - 1) * (q - 1)), 1)
                priv.check()

    def test_compatible_con_tupla(self):
        pub, priv = self.claves[1024]
        n, d = priv
        self.assertEqual(priv, (n, d))
        self.assertEqual(len(priv), 2)
        self.assertNotIn(str(d), repr(priv))  # el repr no filtra d

    def test_crt_igual_a_sin_crt(self):
        """c^d mod n por CRT == sin CRT, con y sin blinding, para 1024 y 2048."""
        for bits, (pub, priv) in self.claves.items():
            n = pub[0]
            for _ in range(5):
                c = secrets.randbelow(n)
                ref = pow(c, priv[1], n)
                with self.subTest(bits=bits):
                    self.assertEqual(rsa_private_op(c, priv), ref)
                    self.assertEqual(rsa_private_op(c, priv, use_crt=False), ref)
                    self.assertEqual(rsa_private_op(c, priv, blinding=False), ref)
                    self.assertEqual(rsa_private_op(c, priv, use_crt=False, blinding=False), ref)
                    self.assertEqual(rsa_private_op(c, (n, priv[1])), ref)

    def test_oaep_con_y_sin_crt(self):
        for bits, (pub, priv) in self.claves.items():
            sin_crt = RSAPrivateKey(priv[0], priv[1], e=priv.e)
            m = b"mensaje de prueba CRT"
            ct = encrypt_oaep(m, pub)
            with self.subTest(bits=bits):
                self.assertEqual(decrypt_oaep(ct, priv), m)
                self.assertEqual(decrypt_oaep(ct, sin_crt), m)
                self.assertEqual(decrypt_oaep(ct, (priv[0], priv[1])), m)

    def test_textbook_con_y_sin_crt(self):
        pub, priv = self.claves[1024]
        m = b"\x00\x00ABC"
        ct = encrypt(m, pub)
        self.assertEqual(decrypt(ct, priv, length=len(m)), m)
        self.assertEqual(decrypt(ct, (priv[0], priv[1]), length=len(m)), m)

    def test_firma_crt_verifica(self):
        for bits, (pub, priv) in self.claves.items():
            with self.subTest(bits=bits):
                s1 = sign(b"doc", priv)
                s2 = sign(b"doc", RSAPrivateKey(priv[0], priv[1], e=priv.e))
                self.assertTrue(verify(b"doc", s1, pub))
                self.assertTrue(verify(b"doc", s2, pub))
                self.assertFalse(verify(b"doc2", s1, pub))

    def test_blinding_usa_r_distinto(self):
        """El blinding no cambia el resultado aunque r cambie en cada llamada."""
        pub, priv = self.claves[1024]
        c = secrets.randbelow(pub[0])
        resultados = {rsa_private_op(c, priv) for _ in range(10)}
        self.assertEqual(len(resultados), 1)

    def test_proteccion_contra_fallos(self):
        """Si la operacion privada devuelve un valor erroneo, sign no entrega la firma."""
        pub, priv = self.claves[1024]
        original = rsa_mod.rsa_private_op
        with mock.patch.object(rsa_mod, "rsa_private_op",
                               side_effect=lambda c, k: (original(c, k) + 1) % k[0]):
            with self.assertRaises(ValueError):
                sign(b"doc", priv)

    def test_entrada_fuera_de_rango(self):
        pub, priv = self.claves[1024]
        with self.assertRaises(ValueError):
            rsa_private_op(pub[0], priv)


class TestFormatoV2(_Base):

    def test_guardar_cargar_v2(self):
        pub, priv = self.claves[1024]
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "priv.json"
            save_private_key(priv, ruta, insecure_plain=True)
            data = json.loads(ruta.read_text(encoding="utf-8"))
            self.assertEqual(data["format"], "rsa-sign-private-v2")
            for campo in ("n", "e", "d", "p", "q", "dp", "dq", "qinv"):
                self.assertTrue(data[campo].startswith("0x"))
            with warnings.catch_warnings():
                warnings.simplefilter("error")  # v2 no debe avisar
                cargada = load_private_key(ruta)
        self.assertTrue(cargada.has_crt)
        self.assertFalse(cargada.legacy)
        self.assertEqual(cargada, priv)
        self.assertEqual((cargada.p, cargada.q, cargada.qinv), (priv.p, priv.q, priv.qinv))

    def test_archivo_antiguo_se_carga(self):
        pub, priv = self.claves[1024]
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "viejo.json"
            ruta.write_text(json.dumps({"n": hex(priv[0]), "d": hex(priv[1])}), encoding="utf-8")
            with self.assertWarns(LegacyKeyFormatWarning):
                cargada = load_private_key(ruta)
        self.assertTrue(cargada.legacy)
        self.assertFalse(cargada.has_crt)
        self.assertEqual(cargada.e, 65537)
        m = b"compatibilidad"
        self.assertEqual(decrypt_oaep(encrypt_oaep(m, pub), cargada), m)
        self.assertTrue(verify(m, sign(m, cargada), pub))

    def test_antiguo_con_e_distinto_desactiva_blinding(self):
        """Si e=65537 no corresponde a d, se descarta e y la clave sigue funcionando."""
        from src.primes import generate_prime
        from src.mathcore import gcd, modinv
        while True:
            p, q = generate_prime(512), generate_prime(512)
            phi = (p - 1) * (q - 1)
            if p != q and gcd(3, phi) == 1:
                break
        n, d = p * q, modinv(3, phi)
        with self.assertWarns(LegacyKeyFormatWarning):
            clave = private_key_from_dict({"n": hex(n), "d": hex(d)})
        self.assertIsNone(clave.e)
        c = secrets.randbelow(n)
        self.assertEqual(rsa_private_op(c, clave), pow(c, d, n))

    def test_v2_incoherente_rechazado(self):
        pub, priv = self.claves[1024]
        data = private_key_to_dict(priv)
        for campo, valor in (("p", hex(priv.p + 2)), ("qinv", hex(priv.qinv + 1)),
                             ("dp", hex(priv.dp + 1)), ("e", hex(3))):
            malo = dict(data, **{campo: valor})
            with self.subTest(campo=campo):
                with self.assertRaises(ValueError):
                    private_key_from_dict(malo)


if __name__ == "__main__":
    unittest.main()
