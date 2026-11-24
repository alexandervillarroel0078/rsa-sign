"""
Pruebas de la Etapa 4: SHA-256 en streaming, generacion de primos/claves,
ataque de Fermat refactorizado y CLI sin tracebacks.
"""

import hashlib  # Solo como referencia.
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src import rsa as rsa_mod
from src.attacks import fermat_attack_rsa, fermat_factor, generate_weak_fermat_key
from src.mathcore import gcd
from src.primes import generate_prime, is_probable_prime
from src.rsa import generate_keypair, sign, sign_hash, verify, verify_hash
from src.sha256 import Sha256, sha256, sha256_file

RAIZ = Path(__file__).resolve().parent.parent


class TestSha256Streaming(unittest.TestCase):

    def test_update_en_trozos_igual_a_hashlib(self):
        for _ in range(30):
            data = secrets.token_bytes(secrets.randbelow(700))
            h = Sha256()
            i = 0
            while i < len(data):
                paso = 1 + secrets.randbelow(130)
                h.update(data[i:i + paso])
                i += paso
            with self.subTest(n=len(data)):
                self.assertEqual(h.digest(), hashlib.sha256(data).digest())
                self.assertEqual(h.digest(), sha256(data))

    def test_digest_no_modifica_y_copy(self):
        h = Sha256(b"abc")
        self.assertEqual(h.hexdigest(), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(h.digest(), h.digest())
        c = h.copy()
        c.update(b"def")
        self.assertEqual(h.digest(), hashlib.sha256(b"abc").digest())
        self.assertEqual(c.digest(), hashlib.sha256(b"abcdef").digest())

    def test_vector_millon_a_en_bloques(self):
        h = Sha256()
        for _ in range(1000):
            h.update(b"a" * 1000)
        self.assertEqual(h.hexdigest(),
                         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

    def test_sha256_file(self):
        data = secrets.token_bytes(200_000)
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "f.bin"
            ruta.write_bytes(data)
            self.assertEqual(sha256_file(ruta, chunk_size=1000), hashlib.sha256(data).digest())
            vacio = Path(tmp) / "v.bin"
            vacio.write_bytes(b"")
            self.assertEqual(sha256_file(vacio), hashlib.sha256(b"").digest())

    def test_sign_hash_equivale_a_sign(self):
        pub, priv = generate_keypair(1024)
        msg = b"documento"
        self.assertTrue(verify_hash(sha256(msg), sign(msg, priv), pub))
        self.assertTrue(verify(msg, sign_hash(sha256(msg), priv), pub))


class TestPrimosYClaves(unittest.TestCase):

    def test_dos_bits_altos(self):
        for bits in (16, 64, 256, 512):
            p = generate_prime(bits)
            with self.subTest(bits=bits):
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p >> (bits - 2), 0b11)

    def test_keygen_rechaza_primos_cercanos(self):
        """Si generate_prime devuelve q muy cercano a p, keygen lo descarta."""
        def primo_valido():
            while True:
                x = generate_prime(256)
                if gcd(65537, x - 1) == 1:
                    return x

        def siguiente_primo_valido(x):
            x += 2
            while not (is_probable_prime(x) and gcd(65537, x - 1) == 1):
                x += 2
            return x

        p = primo_valido()
        q_cerca = siguiente_primo_valido(p)           # |p - q| diminuto
        self.assertLessEqual(abs(q_cerca - p), 1 << (256 - 100))
        q_lejos = primo_valido()
        while abs(q_lejos - p) <= (1 << (256 - 100)):
            q_lejos = primo_valido()
        secuencia = iter([p, q_cerca, q_lejos])
        with mock.patch.object(rsa_mod, "generate_prime", side_effect=lambda b: next(secuencia)):
            pub, _ = rsa_mod.generate_keypair(512)
        self.assertEqual(pub[0], p * q_lejos)

    def test_keygen_tamano_exacto(self):
        for _ in range(5):
            self.assertEqual(generate_keypair(512)[0][0].bit_length(), 512)

    def test_clave_debil_con_e3_siempre_invertible(self):
        for _ in range(10):
            pub, priv = generate_weak_fermat_key(bits=512, e=3)
            m = 12345
            n, e = pub
            self.assertEqual(pow(pow(m, e, n), priv[1], n), m)

    def test_fermat_refactorizado(self):
        self.assertEqual(fermat_factor(10403), (101, 103))
        self.assertIsNone(fermat_factor(3 * 1000003, max_iter=5))
        pub, priv = generate_weak_fermat_key(bits=512)
        r = fermat_attack_rsa(pub, max_iter=100)
        self.assertEqual(r[0], priv)

    def test_pss_clave_pequena_mensaje_claro(self):
        _, priv = generate_keypair(512)
        with self.assertRaises(ValueError) as ctx:
            sign(b"x", priv)
        self.assertIn("demasiado pequena para PSS", str(ctx.exception))


def _cli(*args, entrada="cli.py"):
    """Ejecuta la CLI como proceso aparte y devuelve (codigo, salida)."""
    if entrada == "-m":
        cmd = [sys.executable, "-m", "src.cli", *args]
    else:
        cmd = [sys.executable, str(RAIZ / entrada), *args]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=RAIZ, env=env, timeout=300)
    return r.returncode, r.stdout + r.stderr


class TestCLI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.d = Path(cls._tmp.name)
        cls.pub = str(cls.d / "pub.json")
        cls.priv = str(cls.d / "priv.json")
        codigo, salida = _cli("keygen", "--bits", "1024", "--pub", cls.pub, "--priv", cls.priv)
        assert codigo == 0, salida

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def assertSinTraceback(self, salida):
        self.assertNotIn("Traceback", salida)

    def test_tres_formas_de_ejecutar(self):
        for entrada in ("cli.py", "src/cli.py", "-m"):
            with self.subTest(entrada=entrada):
                codigo, salida = _cli("--help", entrada=entrada)
                self.assertEqual(codigo, 0, salida)
                self.assertIn("keygen", salida)

    def test_msg_vacio_firma_y_verifica(self):
        codigo, salida = _cli("sign", "--key", self.priv, "--msg", "")
        self.assertEqual(codigo, 0, salida)
        firma = salida.strip().split()[-1]
        codigo, salida = _cli("verify", "--key", self.pub, "--msg", "", "--sig", firma)
        self.assertEqual(codigo, 0, salida)
        self.assertIn("EXITOSA", salida)
        codigo, salida = _cli("verify", "--key", self.pub, "--msg", "x", "--sig", firma)
        self.assertEqual(codigo, 1)
        self.assertIn("FALLIDA", salida)

    def test_archivo_por_streaming(self):
        archivo = self.d / "grande.bin"
        archivo.write_bytes(secrets.token_bytes(150_000))
        sig = self.d / "grande.sig"
        codigo, salida = _cli("sign", "--key", self.priv, "--file", str(archivo), "--out", str(sig))
        self.assertEqual(codigo, 0, salida)
        codigo, salida = _cli("verify", "--key", self.pub, "--file", str(archivo), "--sig-file", str(sig))
        self.assertEqual(codigo, 0, salida)

    def test_errores_sin_traceback(self):
        casos = [
            ("verify", "--key", str(self.d / "no_existe.json"), "--msg", "a", "--sig", "00"),
            ("sign", "--key", self.priv, "--file", str(self.d / "no_existe.txt")),
            ("decrypt", "--key", self.priv, "--hex", "zz"),
            ("decrypt", "--key", self.priv, "--hex", "00" * 128),
            ("corrupt", "--hex", "zz"),
            ("corrupt", "--hex", "00", "--bit", "99"),
            ("encrypt", "--key", self.pub, "--msg", "A" * 500),
            ("verify", "--key", self.pub, "--msg", "a", "--sig", "zz"),
            ("keygen", "--bits", "1023"),
        ]
        for args in casos:
            with self.subTest(args=args[:3]):
                codigo, salida = _cli(*args)
                self.assertEqual(codigo, 1, salida)
                self.assertSinTraceback(salida)
                self.assertIn("[-]", salida)

    def test_decrypt_mensaje_generico(self):
        codigo, salida = _cli("decrypt", "--key", self.priv, "--hex", "00" * 128)
        self.assertIn("decryption error", salida)


class TestGuiAutores(unittest.TestCase):

    def test_leer_autores_sin_archivo(self):
        try:
            from src import gui
        except Exception as e:  # sin tkinter
            self.skipTest(f"Tkinter no disponible: {e}")
        with mock.patch.object(gui, "AUTORES_PATH", Path("no_existe_AUTORES")):
            self.assertEqual(gui.leer_autores(), ["<<COMPLETAR>>"])
        self.assertNotIn("Josue", gui.texto_firma_ejemplo())
        self.assertEqual(gui.KEY_SIZES, [1024, 2048, 3072, 4096])


if __name__ == "__main__":
    unittest.main()
