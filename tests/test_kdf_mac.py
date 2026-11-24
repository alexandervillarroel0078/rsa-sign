"""
Pruebas de la Etapa 3: HMAC-SHA256, PBKDF2-HMAC-SHA256 y clave privada cifrada.

hashlib y hmac se usan SOLO como referencia. Ningun test pide contrasena por
teclado: las contrasenas se pasan en codigo o por variable de entorno.
"""

import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src import kdf_mac
from src.kdf_mac import (
    AUTH_ERROR,
    HmacSha256,
    ct_equal,
    decrypt_blob,
    encrypt_blob,
    hmac_sha256,
    pbkdf2_hmac_sha256,
    wipe,
)
from src.rsa import (
    generate_keypair,
    is_encrypted_key_file,
    load_private_key,
    save_private_key,
    sign,
    verify,
)

RAIZ = Path(__file__).resolve().parent.parent
ITER_TEST = 50  # pocas iteraciones para que los tests sean rapidos


class TestHMAC(unittest.TestCase):
    """Vectores de RFC 4231 (HMAC-SHA-256) y comparacion con el modulo hmac."""

    VECTORES = [
        (b"\x0b" * 20, b"Hi There",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (b"\xaa" * 20, b"\xdd" * 50,
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (bytes(range(1, 26)), b"\xcd" * 50,
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (b"\xaa" * 131,
         b"This is a test using a larger than block-size key and a larger than "
         b"block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ]

    def test_rfc4231(self):
        for i, (clave, msg, esperado) in enumerate(self.VECTORES, 1):
            with self.subTest(caso=i):
                self.assertEqual(hmac_sha256(clave, msg).hex(), esperado)

    def test_rfc4231_caso5_truncado(self):
        mac = hmac_sha256(b"\x0c" * 20, b"Test With Truncation")
        self.assertEqual(mac[:16].hex(), "a3b6167473100ee06e0c796c2955552b")

    def test_contra_modulo_hmac(self):
        for _ in range(50):
            clave = secrets.token_bytes(secrets.randbelow(150))
            msg = secrets.token_bytes(secrets.randbelow(300))
            with self.subTest(lk=len(clave), lm=len(msg)):
                self.assertEqual(hmac_sha256(clave, msg), hmac.new(clave, msg, "sha256").digest())

    def test_ruta_rapida_32_bytes(self):
        h = HmacSha256(b"clave")
        for _ in range(20):
            u = secrets.token_bytes(32)
            self.assertEqual(h.mac32_fast(u), h.mac(u))
            self.assertEqual(h.mac32_fast(u), hmac.new(b"clave", u, "sha256").digest())


class TestPBKDF2(unittest.TestCase):

    def test_rfc7914(self):
        """RFC 7914 seccion 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 64)."""
        self.assertEqual(
            pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64).hex(),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        )

    def test_contra_hashlib(self):
        casos = [(b"password", b"salt", 1, 32), (b"password", b"salt", 2, 32),
                 (b"password", b"salt", 100, 32), (b"x" * 100, b"s", 3, 70),
                 (b"", b"salt", 5, 16), ("contrasena con tilde: á".encode(), b"sal", 10, 33)]
        for pw, salt, it, dk in casos:
            with self.subTest(it=it, dk=dk):
                self.assertEqual(pbkdf2_hmac_sha256(pw, salt, it, dk),
                                 hashlib.pbkdf2_hmac("sha256", pw, salt, it, dk))

    def test_acepta_str_y_bytearray(self):
        ref = hashlib.pbkdf2_hmac("sha256", "clave".encode(), b"s", 7, 32)
        self.assertEqual(pbkdf2_hmac_sha256("clave", b"s", 7, 32), ref)
        self.assertEqual(pbkdf2_hmac_sha256(bytearray(b"clave"), b"s", 7, 32), ref)

    def test_parametros_invalidos(self):
        with self.assertRaises(ValueError):
            pbkdf2_hmac_sha256(b"p", b"s", 0, 32)
        with self.assertRaises(TypeError):
            pbkdf2_hmac_sha256(b"p", "s", 1, 32)


class TestUtilidades(unittest.TestCase):

    def test_wipe(self):
        b = bytearray(b"secreto")
        wipe(b)
        self.assertEqual(b, bytearray(7))

    def test_ct_equal(self):
        self.assertTrue(ct_equal(b"abc", b"abc"))
        self.assertFalse(ct_equal(b"abc", b"abd"))
        self.assertFalse(ct_equal(b"abc", b"ab"))

    def test_iteraciones_por_defecto_documentadas(self):
        self.assertGreaterEqual(kdf_mac.DEFAULT_ITERATIONS, 1000)


class TestBlob(unittest.TestCase):

    def test_roundtrip_y_aleatoriedad(self):
        texto = bytearray(b"contenido secreto de la clave privada" * 5)
        a = encrypt_blob(texto, "pw", iterations=ITER_TEST)
        b = encrypt_blob(texto, "pw", iterations=ITER_TEST)
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])  # salt y nonce nuevos
        self.assertEqual(decrypt_blob(a, "pw"), texto)
        for campo in ("version", "kdf", "iterations", "salt", "nonce", "ciphertext", "tag"):
            self.assertIn(campo, a)

    def test_contrasena_vacia(self):
        with self.assertRaises(ValueError):
            encrypt_blob(bytearray(b"x"), "", iterations=ITER_TEST)


class TestClaveCifrada(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = generate_keypair(1024)
        cls._tmp = tempfile.TemporaryDirectory()
        cls.d = Path(cls._tmp.name)
        cls.ruta = cls.d / "priv.json"
        save_private_key(cls.priv, cls.ruta, password="clave correcta", iterations=ITER_TEST)
        cls.blob = json.loads(cls.ruta.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _escribir(self, blob) -> Path:
        ruta = self.d / f"mod_{secrets.token_hex(4)}.json"
        ruta.write_text(json.dumps(blob), encoding="utf-8")
        return ruta

    def _flip(self, hexstr: str, bit: int = 0) -> str:
        datos = bytearray(bytes.fromhex(hexstr))
        datos[0] ^= 1 << bit
        return datos.hex()

    def test_formato_del_archivo(self):
        self.assertTrue(is_encrypted_key_file(self.ruta))
        self.assertEqual(self.blob["version"], "rsa-sign-encrypted-key-v1")
        self.assertEqual(self.blob["kdf"], "pbkdf2-hmac-sha256")
        self.assertEqual(self.blob["iterations"], ITER_TEST)
        contenido = self.ruta.read_text(encoding="utf-8")
        self.assertNotIn(hex(self.priv[1])[2:12], contenido)  # d no aparece en claro
        self.assertNotIn('"d"', contenido)

    def test_roundtrip(self):
        cargada = load_private_key(self.ruta, password="clave correcta")
        self.assertEqual(cargada, self.priv)
        self.assertTrue(cargada.has_crt)
        self.assertTrue(verify(b"doc", sign(b"doc", cargada), self.pub))
        self.assertEqual(load_private_key(self.ruta, password=bytearray(b"clave correcta")), self.priv)

    def test_contrasena_incorrecta(self):
        with self.assertRaises(ValueError) as ctx:
            load_private_key(self.ruta, password="clave incorrecta")
        self.assertEqual(str(ctx.exception), AUTH_ERROR)

    def test_sin_contrasena(self):
        with self.assertRaises(ValueError):
            load_private_key(self.ruta)

    def test_archivo_alterado(self):
        alteraciones = {
            "1 bit del ciphertext": dict(self.blob, ciphertext=self._flip(self.blob["ciphertext"])),
            "1 bit del tag": dict(self.blob, tag=self._flip(self.blob["tag"])),
            "1 bit del salt": dict(self.blob, salt=self._flip(self.blob["salt"])),
            "1 bit del nonce": dict(self.blob, nonce=self._flip(self.blob["nonce"])),
            "iteraciones": dict(self.blob, iterations=ITER_TEST + 1),
            "ciphertext truncado": dict(self.blob, ciphertext=self.blob["ciphertext"][:-2]),
            "tag no hex": dict(self.blob, tag="zz"),
            "sin tag": {k: v for k, v in self.blob.items() if k != "tag"},
        }
        for nombre, blob in alteraciones.items():
            with self.subTest(alteracion=nombre):
                with self.assertRaises(ValueError) as ctx:
                    load_private_key(self._escribir(blob), password="clave correcta")
                self.assertEqual(str(ctx.exception), AUTH_ERROR)

    def test_guardar_sin_contrasena_rechazado(self):
        with self.assertRaises(ValueError):
            save_private_key(self.priv, self.d / "x.json")
        with self.assertRaises(ValueError):
            save_private_key(self.priv, self.d / "y.json", password="a", insecure_plain=True)

    def test_insecure_plain(self):
        ruta = self.d / "plano.json"
        save_private_key(self.priv, ruta, insecure_plain=True)
        self.assertFalse(is_encrypted_key_file(ruta))
        self.assertEqual(load_private_key(ruta), self.priv)

    @unittest.skipIf(os.name == "nt", "En Windows los permisos POSIX no aplican (ACL)")
    def test_permisos_0600(self):
        for ruta in (self.ruta, self.d / "plano600.json"):
            if not ruta.exists():
                save_private_key(self.priv, ruta, insecure_plain=True)
            with self.subTest(ruta=ruta.name):
                self.assertEqual(stat.S_IMODE(os.stat(ruta).st_mode), 0o600)


class TestCLICifrada(unittest.TestCase):
    """Flujo de la CLI con clave cifrada, contrasena por variable de entorno."""

    def _cli(self, *args, password="Grupo-D-2026"):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", RSA_SIGN_PW=password)
        r = subprocess.run([sys.executable, str(RAIZ / "cli.py"), *args], capture_output=True,
                           text=True, cwd=RAIZ, env=env, timeout=60, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def test_keygen_firma_verifica_y_contrasena_incorrecta(self):
        with tempfile.TemporaryDirectory() as tmp:
            pub, priv = str(Path(tmp) / "pub.json"), str(Path(tmp) / "priv.json")
            codigo, salida = self._cli("keygen", "--bits", "1024", "--pub", pub, "--priv", priv,
                                       "--pass-env", "RSA_SIGN_PW")
            self.assertEqual(codigo, 0, salida)
            self.assertTrue(is_encrypted_key_file(priv))

            codigo, salida = self._cli("sign", "--key", priv, "--msg", "hola", "--pass-env", "RSA_SIGN_PW")
            self.assertEqual(codigo, 0, salida)
            firma = salida.strip().split()[-1]
            codigo, salida = self._cli("verify", "--key", pub, "--msg", "hola", "--sig", firma)
            self.assertEqual(codigo, 0, salida)

            codigo, salida = self._cli("sign", "--key", priv, "--msg", "hola", "--pass-env", "RSA_SIGN_PW",
                                       password="otra")
            self.assertEqual(codigo, 1)
            self.assertIn("Contrasena incorrecta", salida)
            self.assertNotIn("Traceback", salida)

            # Sin --pass-env y sin terminal: error claro, no se queda esperando.
            codigo, salida = self._cli("sign", "--key", priv, "--msg", "hola")
            self.assertEqual(codigo, 1)
            self.assertNotIn("Traceback", salida)


class TestGuiClaveCifrada(unittest.TestCase):
    """La GUI guarda cifrado, pide contrasena al cargar y nunca muestra d."""

    def setUp(self):
        try:
            import tkinter as tk
            self.root = tk.Tk()
        except Exception as e:  # sin entorno grafico
            self.skipTest(f"Tkinter no disponible: {e}")
        self.root.withdraw()
        from unittest import mock
        from src import gui
        self.mock, self.gui = mock, gui
        self.app = gui.RSAGuiApp(self.root)
        self._tmp = tempfile.TemporaryDirectory()
        self.ruta = str(Path(self._tmp.name) / "priv.json")
        self.pub, self.priv = generate_keypair(1024)
        self.app.current_pub, self.app.current_priv = self.pub, self.priv

    def tearDown(self):
        self.root.destroy()
        self._tmp.cleanup()

    def test_guardar_y_cargar_cifrado(self):
        m = self.mock
        with m.patch.object(self.gui.filedialog, "asksaveasfilename", return_value=self.ruta), \
             m.patch.object(self.gui, "pedir_contrasena", side_effect=lambda *a, **k: bytearray(b"pw-gui")), \
             m.patch.object(self.gui.messagebox, "showinfo"), \
             m.patch.object(self.gui.messagebox, "showerror") as error, \
             m.patch.object(kdf_mac, "DEFAULT_ITERATIONS", ITER_TEST):
            self.app._guardar_priv_tab1()
        error.assert_not_called()
        self.assertTrue(is_encrypted_key_file(self.ruta))

        self.app.current_priv = None
        with m.patch.object(self.gui.filedialog, "askopenfilename", return_value=self.ruta), \
             m.patch.object(self.gui, "pedir_contrasena", side_effect=lambda *a, **k: bytearray(b"pw-gui")), \
             m.patch.object(self.gui.messagebox, "showerror") as error:
            self.app._cargar_priv_tab1()
        error.assert_not_called()
        self.assertEqual(self.app.current_priv, self.priv)
        texto = self.app.txt_keys.get("1.0", "end")
        self.assertNotIn(str(self.priv[1]), texto)

        with m.patch.object(self.gui.filedialog, "askopenfilename", return_value=self.ruta), \
             m.patch.object(self.gui, "pedir_contrasena", side_effect=lambda *a, **k: bytearray(b"mala")), \
             m.patch.object(self.gui.messagebox, "showerror") as error:
            self.app._cargar_priv_tab1()
        self.assertIn("Contrasena incorrecta", error.call_args[0][1])

    def test_generar_no_muestra_d(self):
        self.app._resultado_keygen = ("ok", (self.pub, self.priv))
        self.app._t0_keygen = 0.0
        self.app._esperar_keygen()
        texto = self.app.txt_keys.get("1.0", "end")
        self.assertNotIn(str(self.priv[1]), texto)
        self.assertIn("no se muestra", texto)


if __name__ == "__main__":
    unittest.main()
