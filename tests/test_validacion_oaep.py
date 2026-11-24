"""
Pruebas de endurecimiento (Etapa 1):
1. Validacion de claves publicas (Zero-Trust) y huella.
2. Cierre del oraculo de relleno OAEP (un unico mensaje de error).
3. RSA textbook: recuperacion de ceros iniciales con longitud fija.
"""

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from src.attacks import demo_e_pequeno, demo_falsificacion_e1, demo_maleabilidad, iroot
from src.oaep import DECRYPTION_ERROR, oaep_decode, oaep_encode
from src.pss import emsa_pss_encode
from src.rsa import (
    decrypt,
    decrypt_oaep,
    encrypt,
    encrypt_oaep,
    generate_keypair,
    load_public_key,
    public_key_fingerprint,
    sign,
    validate_public_key,
    verify,
)
from src.sha256 import sha256


class TestValidacionClavePublica(unittest.TestCase):
    """validate_public_key y su uso en load_public_key, encrypt y verify."""

    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = generate_keypair(1024)
        cls.n = cls.pub[0]

    def test_clave_valida(self):
        self.assertEqual(validate_public_key(self.pub), self.pub)

    def test_claves_invalidas_rechazadas(self):
        n = self.n
        casos = {
            "e=1": (n, 1),
            "e=0": (n, 0),
            "e negativo": (n, -3),
            "e par": (n, 65536),
            "e >= n": (n, n + 2),
            "e == n": (n, n),
            "n par": (n + 1, 65537),
            "n negativo": (-n, 65537),
            "n diminuto": (15, 3),
            "n 512 bits": (generate_keypair(512)[0][0], 65537),
        }
        for nombre, clave in casos.items():
            with self.subTest(caso=nombre):
                with self.assertRaises(ValueError):
                    validate_public_key(clave)
                with self.assertRaises(ValueError):
                    encrypt_oaep(b"x", clave)
                with self.assertRaises(ValueError):
                    verify(b"x", b"\x00" * 128, clave)
                with self.assertRaises(ValueError):
                    encrypt(b"x", clave)

    def test_allow_weak_solo_relaja_tamano(self):
        """allow_weak acepta 512 bits, pero nunca e=1 ni n par."""
        pub512, _ = generate_keypair(512)
        self.assertEqual(validate_public_key(pub512, allow_weak=True), pub512)
        with self.assertRaises(ValueError):
            validate_public_key((pub512[0], 1), allow_weak=True)
        with self.assertRaises(ValueError):
            validate_public_key((pub512[0] + 1, 65537), allow_weak=True)

    def test_tipos_invalidos(self):
        for clave in ("x", (1,), ("n", 3), (True, 3), (self.n, 3.0)):
            with self.subTest(clave=clave):
                with self.assertRaises(TypeError):
                    validate_public_key(clave)

    def test_load_public_key_rechaza_e1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "e1.json"
            ruta.write_text(json.dumps({"n": hex(self.n), "e": "0x1"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(ruta)
            with self.assertRaises(ValueError):
                load_public_key(ruta, allow_weak=True)

    def test_load_public_key_rechaza_512_salvo_allow_weak(self):
        pub512, _ = generate_keypair(512)
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "p512.json"
            ruta.write_text(json.dumps({"n": hex(pub512[0]), "e": hex(pub512[1])}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_public_key(ruta)
            self.assertEqual(load_public_key(ruta, allow_weak=True), pub512)

    def test_falsificacion_e1_ya_no_pasa(self):
        """sig = EM con e = 1 cuadra matematicamente, pero verify la rechaza."""
        msg = b"Pagar 1000000 Bs"
        k = (self.n.bit_length() + 7) // 8
        em = emsa_pss_encode(sha256(msg), self.n.bit_length() - 1)
        firma_falsa = int.from_bytes(em, "big").to_bytes(k, "big")
        with self.assertRaises(ValueError):
            verify(msg, firma_falsa, (self.n, 1))
        r = demo_falsificacion_e1()
        self.assertTrue(r["cuadra_matematicamente"])
        self.assertFalse(r["aceptada"])
        self.assertIsNotNone(r["rechazo"])

    def test_huella(self):
        h = public_key_fingerprint(self.pub)
        self.assertEqual(len(h), 64)
        self.assertEqual(h, public_key_fingerprint(self.pub))
        otra, _ = generate_keypair(1024)
        self.assertNotEqual(h, public_key_fingerprint(otra))
        k = (self.n.bit_length() + 7) // 8
        esperado = sha256(self.n.to_bytes(k, "big") + (65537).to_bytes(3, "big")).hex()
        self.assertEqual(h, esperado)


class TestOraculoOAEP(unittest.TestCase):
    """Todos los fallos de descifrado producen exactamente el mismo mensaje."""

    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = generate_keypair(1024)
        cls.n = cls.pub[0]
        cls.k = 128

    def _error(self, ct, label=b""):
        with self.assertRaises(ValueError) as ctx:
            decrypt_oaep(ct, self.priv, label=label)
        return str(ctx.exception)

    def test_200_criptogramas_aleatorios(self):
        mensajes = set()
        for _ in range(200):
            c = secrets.randbelow(self.n).to_bytes(self.k, "big")
            mensajes.add(self._error(c))
        self.assertEqual(mensajes, {DECRYPTION_ERROR})

    def test_criptogramas_manipulados(self):
        legitimo = encrypt_oaep(b"contenido", self.pub, label=b"L")
        mensajes = set()
        for pos in (0, 1, 31, 64, 127):
            alterado = bytearray(legitimo)
            alterado[pos] ^= 0x01
            mensajes.add(self._error(bytes(alterado), label=b"L"))
        mensajes.add(self._error(legitimo, label=b"otra"))          # etiqueta distinta
        mensajes.add(self._error(legitimo[:-1], label=b"L"))        # longitud
        mensajes.add(self._error(b"", label=b"L"))                  # vacio
        mensajes.add(self._error((self.n + 1).to_bytes(self.k, "big"), label=b"L"))  # c >= n
        self.assertEqual(mensajes, {DECRYPTION_ERROR})

    def test_decode_bloques_malformados(self):
        """oaep_decode a nivel de bloque: cada tipo de fallo, mismo mensaje."""
        k = 128
        em = bytearray(oaep_encode(b"hola", k))
        casos = []
        y_mal = bytearray(em); y_mal[0] = 0x01; casos.append(bytes(y_mal))
        casos.append(bytes(k))  # todo ceros: lHash no coincide
        casos.append(bytes(em[:-1]))  # longitud
        for c in casos:
            with self.subTest(c=c[:4].hex()):
                with self.assertRaises(ValueError) as ctx:
                    oaep_decode(c, k)
                self.assertEqual(str(ctx.exception), DECRYPTION_ERROR)
        with self.assertRaises(ValueError) as ctx:
            oaep_decode(bytes(em), k, label=b"x")
        self.assertEqual(str(ctx.exception), DECRYPTION_ERROR)

    def test_roundtrip_intacto(self):
        for m in (b"", b"\x00", b"\x01\x01", b"\x00\x01" * 31):
            with self.subTest(m=m):
                self.assertEqual(decrypt_oaep(encrypt_oaep(m, self.pub), self.priv), m)


class TestTextbook(unittest.TestCase):
    """RSA textbook: solo demostracion, pero correcto."""

    def test_ceros_iniciales(self):
        pub, priv = generate_keypair(1024)
        k = 128
        m = b"\x00\x00ABC"
        ct = encrypt(m, pub)
        self.assertEqual(decrypt(ct, priv, length=len(m)), m)
        self.assertEqual(decrypt(ct, priv, length=k), m.rjust(k, b"\x00"))
        # Sin longitud se pierden (comportamiento documentado).
        self.assertEqual(decrypt(ct, priv), b"ABC")

    def test_demo_maleabilidad(self):
        r = demo_maleabilidad()
        self.assertEqual(r["descifrado_del_forjado"], r["a"] * r["b"])
        self.assertTrue(r["determinista"])
        self.assertEqual(r["diccionario"], [b"NO"])

    def test_demo_e_pequeno(self):
        self.assertTrue(demo_e_pequeno()["exito"])

    def test_iroot(self):
        for _ in range(50):
            x = secrets.randbits(600)
            r = iroot(x, 3)
            self.assertLessEqual(r ** 3, x)
            self.assertGreater((r + 1) ** 3, x)
        self.assertEqual(iroot(0, 3), 0)
        self.assertEqual(iroot(27, 3), 3)


if __name__ == "__main__":
    unittest.main()
