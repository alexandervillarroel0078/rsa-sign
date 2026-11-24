"""
Interfaz Grafica de Usuario (GUI) en Tkinter con 5 pestanas para el sistema RSA-Sign.

Pestanas:
1. Generacion de Claves RSA (n, e, d) con guardado en archivo JSON.
2. Cifrado RSA-OAEP con relleno probabilistico seguro.
3. Descifrado RSA-OAEP con verificacion de integridad.
4. Firma Digital RSA-PSS sobre SHA-256 con salt aleatorio.
5. Verificacion en Tiempo Constante y Demostracion de Ataques (Fermat y alteracion de 1 bit).
"""

import threading
import time
import warnings
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

from .rsa import (
    generate_keypair,
    save_public_key,
    load_public_key,
    save_private_key,
    load_private_key,
    is_encrypted_key_file,
    encrypt_oaep,
    decrypt_oaep,
    sign,
    verify,
    public_key_fingerprint,
)
from .attacks import (
    fermat_attack_rsa,
    generate_weak_fermat_key,
    corrupt_bit,
)
from .sha256 import sha256_hex
from . import kdf_mac

# rsa.save_*_key / load_*_key usan JSON con n, e, d en hexadecimal (no PEM).
KEY_EXT = ".json"
KEY_FILETYPES = [("Archivos JSON", "*.json"), ("Todos", "*.*")]

# Tamanos ofrecidos. 512 no se ofrece: no admite OAEP ni PSS con SHA-256.
KEY_SIZES = [1024, 2048, 3072, 4096]

# Archivo con los integrantes (uno por linea, '#' = comentario) en la raiz.
AUTORES_PATH = Path(__file__).resolve().parent.parent / "AUTORES"
AUTOR_POR_DEFECTO = "<<COMPLETAR>>"


def leer_autores() -> list:
    """Lee los integrantes desde AUTORES. Si no existe, devuelve [AUTOR_POR_DEFECTO]."""
    try:
        lineas = AUTORES_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [AUTOR_POR_DEFECTO]
    autores = [l.strip() for l in lineas if l.strip() and not l.strip().startswith("#")]
    return autores or [AUTOR_POR_DEFECTO]


def pedir_contrasena(parent, titulo: str, confirmar: bool = False):
    """
    Dialogo de contrasena (caracteres ocultos con '*'). Devuelve un bytearray
    (borrable con kdf_mac.wipe) o None si se cancela.

    Limitacion: tkinter entrega la contrasena como str inmutable; se convierte
    a bytearray y se descarta la referencia, pero la copia str no se puede
    sobrescribir.
    """
    texto = simpledialog.askstring(titulo, "Contrasena de la clave privada:", show="*", parent=parent)
    if not texto:
        return None
    pw = bytearray(texto.encode("utf-8"))
    del texto
    if confirmar:
        otra = simpledialog.askstring(titulo, "Repita la contrasena:", show="*", parent=parent)
        iguales = otra is not None and bytearray(otra.encode("utf-8")) == pw
        del otra
        if not iguales:
            kdf_mac.wipe(pw)
            messagebox.showerror("Error", "Las contrasenas no coinciden.", parent=parent)
            return None
    return pw


def describir_privada(priv) -> str:
    """Resumen de la clave privada SIN mostrar d, p ni q."""
    crt = "si" if getattr(priv, "p", None) else "no"
    texto = f"En memoria (no se muestra). Modulo de {priv[0].bit_length()} bits, CRT: {crt}."
    if getattr(priv, "legacy", False):
        texto += ("\n[!] Formato antiguo {n, d}: no incluye p ni q (sin CRT). "
                  "Genere un par nuevo para tener CRT y guardarlo cifrado.")
    return texto


def texto_firma_ejemplo() -> str:
    return f"Yo, {leer_autores()[0]}, firmo electronicamente este documento."


class RSAGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-Sign | Sistema Criptografico Universitario")
        self.root.geometry("860x680")
        self.root.minsize(780, 580)

        # Estado global de claves en sesion
        self.current_pub = None
        self.current_priv = None

        self._crear_interfaz()

    def _crear_interfaz(self):
        # Cuaderno de pestanas (Notebook)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Crear las 5 pestanas solicitadas
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        self.tab4 = ttk.Frame(self.notebook)
        self.tab5 = ttk.Frame(self.notebook)

        self.notebook.add(self.tab1, text="1. Claves RSA")
        self.notebook.add(self.tab2, text="2. Cifrado OAEP")
        self.notebook.add(self.tab3, text="3. Descifrado OAEP")
        self.notebook.add(self.tab4, text="4. Firma PSS")
        self.notebook.add(self.tab5, text="5. Verificacion y Ataques")

        self._init_tab1()
        self._init_tab2()
        self._init_tab3()
        self._init_tab4()
        self._init_tab5()

    # --------------------------------------------------------------------------
    # PESTANA 1: GENERACION Y GESTION DE CLAVES
    # --------------------------------------------------------------------------
    def _init_tab1(self):
        f_top = ttk.LabelFrame(self.tab1, text="Parametros de Generacion")
        f_top.pack(fill="x", padx=10, pady=5)

        ttk.Label(f_top, text="Tamano de clave (bits):").pack(side="left", padx=5, pady=5)
        self.var_bits = tk.IntVar(value=2048)
        c_bits = ttk.Combobox(f_top, textvariable=self.var_bits, values=KEY_SIZES, width=8, state="readonly")
        c_bits.pack(side="left", padx=5, pady=5)

        self.btn_gen = ttk.Button(f_top, text="Generar Nuevas Claves", command=self._generar_claves)
        self.btn_gen.pack(side="left", padx=15, pady=5)

        # Indicador de progreso (indeterminado) mientras se buscan los primos.
        self.progress = ttk.Progressbar(f_top, mode="indeterminate", length=90)
        self.progress.pack(side="left", padx=5, pady=5)

        btn_load_pub = ttk.Button(f_top, text="Cargar Clave Publica...", command=self._cargar_pub_tab1)
        btn_load_pub.pack(side="right", padx=5, pady=5)
        btn_load_priv = ttk.Button(f_top, text="Cargar Clave Privada...", command=self._cargar_priv_tab1)
        btn_load_priv.pack(side="right", padx=5, pady=5)

        # Visualizador de componentes
        f_body = ttk.LabelFrame(self.tab1, text="Parametros Criptograficos Generados")
        f_body.pack(fill="both", expand=True, padx=10, pady=5)

        self.txt_keys = scrolledtext.ScrolledText(f_body, wrap="char", height=18)
        self.txt_keys.pack(fill="both", expand=True, padx=5, pady=5)

        f_bottom = ttk.Frame(self.tab1)
        f_bottom.pack(fill="x", padx=10, pady=5)
        btn_save_pub = ttk.Button(f_bottom, text="Guardar Clave Publica (.json)", command=self._guardar_pub_tab1)
        btn_save_pub.pack(side="left", padx=5)
        btn_save_priv = ttk.Button(f_bottom, text="Guardar Clave Privada (.json)", command=self._guardar_priv_tab1)
        btn_save_priv.pack(side="left", padx=5)

    def _generar_claves(self):
        """
        Lanza la generacion en un hilo aparte para no congelar la ventana.
        Tkinter no es seguro entre hilos: el hilo solo deja el resultado en
        self._resultado_keygen y el hilo principal lo recoge con after().
        """
        bits = self.var_bits.get()
        self.txt_keys.delete("1.0", "end")
        aviso = " (puede tardar varios segundos)" if bits >= 3072 else ""
        self.txt_keys.insert("end", f"[*] Generando par de claves RSA de {bits} bits{aviso}...\n")
        self.btn_gen.state(["disabled"])
        self.progress.start(12)
        self._resultado_keygen = None
        self._t0_keygen = time.perf_counter()

        def trabajo():
            try:
                self._resultado_keygen = ("ok", generate_keypair(bits=bits))
            except Exception as err:  # se reporta en el hilo principal
                self._resultado_keygen = ("error", err)

        threading.Thread(target=trabajo, daemon=True).start()
        self.root.after(100, self._esperar_keygen)

    def _esperar_keygen(self):
        if self._resultado_keygen is None:
            self.root.after(100, self._esperar_keygen)
            return
        self.progress.stop()
        self.btn_gen.state(["!disabled"])
        estado, valor = self._resultado_keygen
        if estado == "error":
            messagebox.showerror("Error", f"No se pudo generar la clave: {valor}")
            return
        elapsed = time.perf_counter() - self._t0_keygen
        self.current_pub, self.current_priv = valor

        # La clave privada (d, p, q) nunca se muestra en pantalla.
        n, e = self.current_pub
        texto = (
            f"[+] Claves generadas exitosamente en {elapsed:.3f} segundos.\n\n"
            f"=== CLAVE PUBLICA ===\n"
            f"Modulo n ({n.bit_length()} bits):\n{n}\n\n"
            f"Exponente e:\n{e}\n\n"
            f"Huella SHA-256 (n || e):\n{public_key_fingerprint(self.current_pub)}\n\n"
            f"=== CLAVE PRIVADA ===\n"
            f"{describir_privada(self.current_priv)}\n"
            f"Guardela con 'Guardar Clave Privada': se cifra con contrasena.\n"
        )
        self.txt_keys.delete("1.0", "end")
        self.txt_keys.insert("end", texto)

    def _guardar_pub_tab1(self):
        if not self.current_pub:
            messagebox.showwarning("Atencion", "No hay una clave publica generada o cargada.")
            return
        path = filedialog.asksaveasfilename(
            title="Guardar clave publica",
            initialfile="clave_publica",
            defaultextension=KEY_EXT,
            filetypes=KEY_FILETYPES,
        )
        if path:
            save_public_key(self.current_pub, path)
            messagebox.showinfo("Guardado", f"Clave publica guardada en:\n{path}")

    def _guardar_priv_tab1(self):
        if not self.current_priv:
            messagebox.showwarning("Atencion", "No hay una clave privada generada o cargada.")
            return
        path = filedialog.asksaveasfilename(
            title="Guardar clave privada",
            initialfile="clave_privada",
            defaultextension=KEY_EXT,
            filetypes=KEY_FILETYPES,
        )
        if not path:
            return
        pw = pedir_contrasena(self.root, "Cifrar clave privada", confirmar=True)
        if pw is None:
            return
        try:
            save_private_key(self.current_priv, path, password=pw)
            messagebox.showinfo("Guardado", f"Clave privada guardada CIFRADA en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar la clave privada: {e}")
        finally:
            kdf_mac.wipe(pw)

    def _cargar_pub_tab1(self):
        path = filedialog.askopenfilename(
            title="Cargar clave publica",
            initialfile="clave_publica" + KEY_EXT,
            defaultextension=KEY_EXT,
            filetypes=KEY_FILETYPES,
        )
        if path:
            try:
                self.current_pub = load_public_key(path)
                self.txt_keys.delete("1.0", "end")
                self.txt_keys.insert(
                    "end",
                    f"[+] Clave publica cargada desde {path}:\nn: {self.current_pub[0]}\ne: {self.current_pub[1]}\n"
                    f"Huella SHA-256: {public_key_fingerprint(self.current_pub)}\n",
                )
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar clave publica: {e}")

    def _cargar_priv_tab1(self):
        path = filedialog.askopenfilename(
            title="Cargar clave privada",
            initialfile="clave_privada" + KEY_EXT,
            defaultextension=KEY_EXT,
            filetypes=KEY_FILETYPES,
        )
        if path:
            pw = None
            if is_encrypted_key_file(path):
                pw = pedir_contrasena(self.root, "Desbloquear clave privada")
                if pw is None:
                    return
            try:
                # La privada la usan Descifrado y Firma; la publica (n, e) se
                # carga aparte y no se deriva de aqui. d nunca se muestra.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # el formato antiguo se indica en el texto
                    self.current_priv = load_private_key(path, password=pw)
                self.txt_keys.delete("1.0", "end")
                self.txt_keys.insert(
                    "end",
                    f"[+] Clave privada cargada desde {path}:\n{describir_privada(self.current_priv)}\n",
                )
            except ValueError as e:
                if str(e) == kdf_mac.AUTH_ERROR:
                    messagebox.showerror("Error", "Contrasena incorrecta o archivo de clave alterado.")
                else:
                    messagebox.showerror("Error", f"Error al cargar clave privada: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar clave privada: {e}")
            finally:
                kdf_mac.wipe(pw)

    # --------------------------------------------------------------------------
    # PESTANA 2: CIFRADO RSA-OAEP
    # --------------------------------------------------------------------------
    def _init_tab2(self):
        f_msg = ttk.LabelFrame(self.tab2, text="Mensaje en Texto Claro a Cifrar")
        f_msg.pack(fill="x", padx=10, pady=5)
        self.txt_enc_in = scrolledtext.ScrolledText(f_msg, height=5)
        self.txt_enc_in.pack(fill="x", padx=5, pady=5)
        self.txt_enc_in.insert("end", "Mensaje confidencial cifrado con relleno OAEP y SHA-256.")

        f_opt = ttk.Frame(self.tab2)
        f_opt.pack(fill="x", padx=10, pady=5)
        ttk.Label(f_opt, text="Etiqueta opcional (Label):").pack(side="left", padx=5)
        self.ent_enc_label = ttk.Entry(f_opt, width=30)
        self.ent_enc_label.pack(side="left", padx=5)

        btn_enc = ttk.Button(f_opt, text="Cifrar con RSA-OAEP", command=self._cifrar_oaep)
        btn_enc.pack(side="right", padx=5)

        f_res = ttk.LabelFrame(self.tab2, text="Resultado del Criptograma (Hexadecimal)")
        f_res.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_enc_out = scrolledtext.ScrolledText(f_res, wrap="char", height=10)
        self.txt_enc_out.pack(fill="both", expand=True, padx=5, pady=5)

    def _cifrar_oaep(self):
        if not self.current_pub:
            messagebox.showwarning("Atencion", "Primero genera o carga una Clave Publica en la Pestana 1.")
            return

        msg = self.txt_enc_in.get("1.0", "end-1c").encode("utf-8")
        if not msg:
            messagebox.showwarning("Atencion", "El mensaje no puede estar vacio.")
            return

        label = self.ent_enc_label.get().encode("utf-8")

        try:
            c = encrypt_oaep(msg, self.current_pub, label=label)
            self.txt_enc_out.delete("1.0", "end")
            self.txt_enc_out.insert("end", c.hex())
        except Exception as e:
            messagebox.showerror("Error de Cifrado", str(e))

    # --------------------------------------------------------------------------
    # PESTANA 3: DESCIFRADO RSA-OAEP
    # --------------------------------------------------------------------------
    def _init_tab3(self):
        f_crip = ttk.LabelFrame(self.tab3, text="Criptograma en Hexadecimal a Descifrar")
        f_crip.pack(fill="x", padx=10, pady=5)
        self.txt_dec_in = scrolledtext.ScrolledText(f_crip, height=6)
        self.txt_dec_in.pack(fill="x", padx=5, pady=5)

        f_opt = ttk.Frame(self.tab3)
        f_opt.pack(fill="x", padx=10, pady=5)
        ttk.Label(f_opt, text="Etiqueta asociada (Label):").pack(side="left", padx=5)
        self.ent_dec_label = ttk.Entry(f_opt, width=30)
        self.ent_dec_label.pack(side="left", padx=5)

        btn_dec = ttk.Button(f_opt, text="Descifrar con RSA-OAEP", command=self._descifrar_oaep)
        btn_dec.pack(side="right", padx=5)

        f_res = ttk.LabelFrame(self.tab3, text="Texto Claro Descifrado")
        f_res.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_dec_out = scrolledtext.ScrolledText(f_res, wrap="word", height=8)
        self.txt_dec_out.pack(fill="both", expand=True, padx=5, pady=5)

    def _descifrar_oaep(self):
        if not self.current_priv:
            messagebox.showwarning("Atencion", "Primero genera o carga una Clave Privada en la Pestana 1.")
            return

        hex_data = self.txt_dec_in.get("1.0", "end").strip()
        if not hex_data:
            messagebox.showwarning("Atencion", "Pegue el criptograma en hexadecimal a descifrar.")
            return

        try:
            c_bytes = bytes.fromhex(hex_data)
        except ValueError:
            messagebox.showerror("Error de Descifrado", "El criptograma no es hexadecimal valido.")
            return
        try:
            label = self.ent_dec_label.get().encode("utf-8")
            plano = decrypt_oaep(c_bytes, self.current_priv, label=label)
            self.txt_dec_out.delete("1.0", "end")
            self.txt_dec_out.insert("end", plano.decode("utf-8", errors="replace"))
        except ValueError:
            # Mensaje unico y fijo: no se revela la causa (evita oraculo de relleno).
            messagebox.showerror("Error de Descifrado", "decryption error")

    # --------------------------------------------------------------------------
    # PESTANA 4: FIRMA DIGITAL RSA-PSS
    # --------------------------------------------------------------------------
    def _init_tab4(self):
        f_msg = ttk.LabelFrame(self.tab4, text="Mensaje / Documento a Firmar")
        f_msg.pack(fill="x", padx=10, pady=5)
        self.txt_sign_in = scrolledtext.ScrolledText(f_msg, height=5)
        self.txt_sign_in.pack(fill="x", padx=5, pady=5)
        self.txt_sign_in.insert("end", texto_firma_ejemplo())

        f_btn = ttk.Frame(self.tab4)
        f_btn.pack(fill="x", padx=10, pady=5)
        btn_firmar = ttk.Button(f_btn, text="Generar Firma Digital RSA-PSS", command=self._firmar_pss)
        btn_firmar.pack(side="left", padx=5)

        f_res = ttk.LabelFrame(self.tab4, text="Detalles de la Firma Digital")
        f_res.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_sign_out = scrolledtext.ScrolledText(f_res, wrap="char", height=12)
        self.txt_sign_out.pack(fill="both", expand=True, padx=5, pady=5)

    def _firmar_pss(self):
        if not self.current_priv:
            messagebox.showwarning("Atencion", "Primero genera o carga una Clave Privada en la Pestana 1.")
            return

        msg = self.txt_sign_in.get("1.0", "end-1c").encode("utf-8")
        if not msg:
            messagebox.showwarning("Atencion", "El mensaje a firmar no puede estar vacio.")
            return

        try:
            h_hex = sha256_hex(msg)
            firma = sign(msg, self.current_priv)
            texto = (
                f"[+] Documento firmado exitosamente.\n"
                f"Longitud del mensaje: {len(msg)} bytes\n"
                f"Hash SHA-256 (mHash): {h_hex}\n"
                f"Longitud de la firma: {len(firma)} bytes ({len(firma)*8} bits)\n\n"
                f"=== FIRMA DIGITAL RSA-PSS (Hexadecimal) ===\n"
                f"{firma.hex()}\n"
            )
            self.txt_sign_out.delete("1.0", "end")
            self.txt_sign_out.insert("end", texto)
        except Exception as e:
            messagebox.showerror("Error al Firmar", str(e))

    # --------------------------------------------------------------------------
    # PESTANA 5: VERIFICACION Y PRUEBAS DE ATAQUE
    # --------------------------------------------------------------------------
    def _init_tab5(self):
        f_ver = ttk.LabelFrame(self.tab5, text="A. Verificacion de Firma (Tiempo Constante)")
        f_ver.pack(fill="x", padx=10, pady=5)

        f_ver_grid = ttk.Frame(f_ver)
        f_ver_grid.pack(fill="x", padx=5, pady=5)

        ttk.Label(f_ver_grid, text="Mensaje:").grid(row=0, column=0, sticky="w")
        self.ent_ver_msg = ttk.Entry(f_ver_grid, width=70)
        self.ent_ver_msg.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.ent_ver_msg.insert("0", texto_firma_ejemplo())

        ttk.Label(f_ver_grid, text="Firma Hex:").grid(row=1, column=0, sticky="w")
        self.ent_ver_sig = ttk.Entry(f_ver_grid, width=70)
        self.ent_ver_sig.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        f_ver_btns = ttk.Frame(f_ver)
        f_ver_btns.pack(fill="x", padx=5, pady=5)
        btn_verificar = ttk.Button(f_ver_btns, text="Verificar Firma PSS", command=self._verificar_firma)
        btn_verificar.pack(side="left", padx=5)

        # Ataque 1: Alteracion de 1 bit
        f_att_bit = ttk.LabelFrame(self.tab5, text="B. Ataque por Alteracion de 1 Bit")
        f_att_bit.pack(fill="x", padx=10, pady=5)

        btn_flip_sig = ttk.Button(f_att_bit, text="Alterar 1 Bit en la Firma", command=self._alterar_bit_firma)
        btn_flip_sig.pack(side="left", padx=5, pady=5)
        btn_flip_msg = ttk.Button(f_att_bit, text="Alterar 1 Bit en el Mensaje", command=self._alterar_bit_msg)
        btn_flip_msg.pack(side="left", padx=5, pady=5)

        # Ataque 2: Factorizacion de Fermat
        f_att_fermat = ttk.LabelFrame(self.tab5, text="C. Ataque de Factorizacion de Fermat (SOLO DEMOSTRACION)")
        f_att_fermat.pack(fill="both", expand=True, padx=10, pady=5)

        f_fermat_top = ttk.Frame(f_att_fermat)
        f_fermat_top.pack(fill="x", padx=5, pady=5)
        btn_gen_weak = ttk.Button(f_fermat_top, text="Generar Clave Debil (Primos Cercanos)", command=self._generar_clave_debil)
        btn_gen_weak.pack(side="left", padx=5)
        btn_run_fermat = ttk.Button(f_fermat_top, text="Ejecutar Ataque de Fermat", command=self._ejecutar_fermat)
        btn_run_fermat.pack(side="left", padx=5)

        self.txt_fermat_out = scrolledtext.ScrolledText(f_att_fermat, wrap="char", height=9)
        self.txt_fermat_out.pack(fill="both", expand=True, padx=5, pady=5)

    def _verificar_firma(self):
        if not self.current_pub:
            messagebox.showwarning("Atencion", "Primero genera o carga una Clave Publica en la Pestana 1.")
            return

        msg = self.ent_ver_msg.get().encode("utf-8")
        sig_hex = self.ent_ver_sig.get().strip()

        if not sig_hex:
            messagebox.showwarning("Atencion", "Ingrese la firma en hexadecimal.")
            return

        msg_fallida = "[-] VERIFICACION FALLIDA:\nLa firma es INVALIDA o el mensaje fue adulterado."

        # Una firma con caracteres no hexadecimales o longitud impar no puede ser
        # valida: se rechaza con el mismo mensaje, sin mostrar el error interno.
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            messagebox.showerror("Resultado", msg_fallida)
            return

        try:
            es_valida = verify(msg, sig, self.current_pub)
            if es_valida:
                messagebox.showinfo("Resultado", "[+] VERIFICACION EXITOSA:\nLa firma digital es AUTENTICA y no ha sido alterada.")
            else:
                messagebox.showerror("Resultado", msg_fallida)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _alterar_bit_firma(self):
        sig_hex = self.ent_ver_sig.get().strip()
        if not sig_hex:
            messagebox.showwarning("Atencion", "No hay firma cargada en el campo.")
            return
        try:
            sig = bytes.fromhex(sig_hex)
            sig_alt = corrupt_bit(sig, bit_index=0)
            self.ent_ver_sig.delete(0, "end")
            self.ent_ver_sig.insert(0, sig_alt.hex())
            messagebox.showinfo("Ataque de 1 bit", "Se ha invertido exactamente el bit 0 de la firma.\nPrueba ahora 'Verificar Firma PSS' para ver el rechazo.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _alterar_bit_msg(self):
        msg = self.ent_ver_msg.get().encode("utf-8")
        if not msg:
            return
        try:
            msg_alt = corrupt_bit(msg, bit_index=0)
            self.ent_ver_msg.delete(0, "end")
            self.ent_ver_msg.insert(0, msg_alt.decode("utf-8", errors="replace"))
            messagebox.showinfo("Ataque de 1 bit", "Se ha alterado 1 bit en el mensaje.\nPrueba ahora 'Verificar Firma PSS' para ver el rechazo.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _generar_clave_debil(self):
        self.txt_fermat_out.delete("1.0", "end")
        self.txt_fermat_out.insert("end", "[*] Generando clave vulnerable (p y q consecutivos de 512 bits cada uno)...\n")
        self.root.update()

        self.weak_pub, self.weak_priv = generate_weak_fermat_key(bits=1024)
        self.txt_fermat_out.insert("end", f"[+] Clave debil creada.\nModulo n ({self.weak_pub[0].bit_length()} bits):\n{self.weak_pub[0]}\n\n")

    def _ejecutar_fermat(self):
        if not hasattr(self, "weak_pub") or not self.weak_pub:
            messagebox.showwarning("Atencion", "Primero genera una clave debil con el boton anterior.")
            return

        self.txt_fermat_out.insert("end", "[*] Ejecutando ataque de factorizacion de Fermat...\n")
        self.root.update()

        t0 = time.time()
        res = fermat_attack_rsa(self.weak_pub, max_iter=10000)
        elapsed = time.time() - t0

        if res is None:
            self.txt_fermat_out.insert("end", "[-] Ataque fallido.\n")
        else:
            priv, (p, q), it = res
            self.txt_fermat_out.insert(
                "end",
                f"[+] EXITO: Modulo factorizado en {it} iteracion(es) ({elapsed*1000:.2f} ms)!\n"
                f"p: {p}\n"
                f"q: {q}\n"
                f"Clave privada reconstruida d:\n{priv[1]}\n"
                f"[!] Coincide exactamente con la clave privada real: {priv == self.weak_priv}\n"
            )


def main():
    root = tk.Tk()
    app = RSAGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
