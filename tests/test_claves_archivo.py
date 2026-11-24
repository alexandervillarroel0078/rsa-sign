"""
Pruebas de ida y vuelta con claves guardadas en archivo.

generate_keypair -> save -> load (publica y privada) -> usar las claves cargadas
para OAEP (cifrar/descifrar) y PSS (firmar/verificar). Tambien comprueba que los
handlers de carga de la GUI guardan las tuplas cargadas sin errores.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.rsa import (
    decrypt_oaep,
    encrypt_oaep,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign,
    verify,
)


class TestClavesDesdeArchivo(unittest.TestCase):
    """Las claves cargadas desde JSON funcionan igual que las generadas."""

    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = generate_keypair(1024)
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        cls.ruta_pub = tmp / "clave_publica.json"
        cls.ruta_priv = tmp / "clave_privada.json"
        save_public_key(cls.pub, cls.ruta_pub)
        save_private_key(cls.priv, cls.ruta_priv, insecure_plain=True)
        cls.pub_cargada = load_public_key(cls.ruta_pub)
        cls.priv_cargada = load_private_key(cls.ruta_priv)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_carga_devuelve_las_mismas_tuplas(self):
        """load devuelve exactamente (n, e) y (n, d) como tuplas."""
        self.assertIsInstance(self.pub_cargada, tuple)
        self.assertIsInstance(self.priv_cargada, tuple)
        self.assertEqual(self.pub_cargada, self.pub)
        self.assertEqual(self.priv_cargada, self.priv)

    def test_oaep_con_claves_cargadas(self):
        """Cifrar con la publica cargada y descifrar con la privada cargada."""
        mensaje = "Mensaje de prueba OAEP con claves desde archivo".encode("utf-8")
        criptograma = encrypt_oaep(mensaje, self.pub_cargada)
        self.assertEqual(decrypt_oaep(criptograma, self.priv_cargada), mensaje)

    def test_pss_con_claves_cargadas(self):
        """Firmar con la privada cargada y verificar con la publica cargada."""
        mensaje = b"Documento firmado con claves desde archivo"
        firma = sign(mensaje, self.priv_cargada)
        self.assertTrue(verify(mensaje, firma, self.pub_cargada))
        self.assertFalse(verify(mensaje + b"!", firma, self.pub_cargada))


class TestGuiCargaClaves(unittest.TestCase):
    """Los handlers de la pestana 1 cargan las tuplas sin usar atributos de objeto."""

    def setUp(self):
        try:
            import tkinter as tk
            self.root = tk.Tk()
        except Exception as e:  # sin entorno grafico (p. ej. CI sin display)
            self.skipTest(f"Tkinter no disponible: {e}")
        self.root.withdraw()
        from src import gui
        self.gui = gui
        self.app = gui.RSAGuiApp(self.root)
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.pub, self.priv = generate_keypair(1024)
        self.ruta_pub = str(tmp / "clave_publica.json")
        self.ruta_priv = str(tmp / "clave_privada.json")
        save_public_key(self.pub, self.ruta_pub)
        save_private_key(self.priv, self.ruta_priv, insecure_plain=True)

    def tearDown(self):
        self.root.destroy()
        self._tmp.cleanup()

    def _cargar(self, handler, ruta):
        with mock.patch.object(self.gui.filedialog, "askopenfilename", return_value=ruta), \
             mock.patch.object(self.gui.messagebox, "showerror") as error:
            handler()
        return error

    def test_cargar_privada_sin_error(self):
        """Cargar la privada guarda (n, d), no toca la publica y NO muestra d (Etapa 3)."""
        error = self._cargar(self.app._cargar_priv_tab1, self.ruta_priv)
        error.assert_not_called()
        self.assertEqual(self.app.current_priv, self.priv)
        self.assertIsNone(self.app.current_pub)
        texto = self.app.txt_keys.get("1.0", "end")
        self.assertIn(f"[+] Clave privada cargada desde {self.ruta_priv}", texto)
        self.assertIn("1024 bits", texto)
        self.assertNotIn(str(self.priv[1]), texto)

    def test_cargar_publica_sin_error(self):
        """Cargar la publica guarda (n, e) y muestra n y e."""
        error = self._cargar(self.app._cargar_pub_tab1, self.ruta_pub)
        error.assert_not_called()
        self.assertEqual(self.app.current_pub, self.pub)
        texto = self.app.txt_keys.get("1.0", "end")
        self.assertIn(f"[+] Clave publica cargada desde {self.ruta_pub}", texto)
        self.assertIn(f"e: {self.pub[1]}", texto)


if __name__ == "__main__":
    unittest.main()
