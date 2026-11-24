"""Demo local de rsa-sign: claves, OAEP y firma PSS con SHA-256 (1024 bits)."""

import time

from src.rsa import generate_keypair, encrypt_oaep, decrypt_oaep, sign, verify

BITS = 1024

# 1. Generacion de claves
t0 = time.perf_counter()
public, private = generate_keypair(BITS)
t = time.perf_counter() - t0
n, e = public
print("=== 1. Generacion de claves ===")
print(f"Tiempo: {t:.3f} s")
print(f"Tamano de n: {n.bit_length()} bits ({(n.bit_length() + 7) // 8} bytes)")
print(f"e = {e}")
print(f"n = {hex(n)[:34]}...")

# 2. Cifrado / descifrado OAEP
print("\n=== 2. Cifrado OAEP ===")
msg = "Hola Grupo D, mensaje secreto de prueba".encode("utf-8")
ct = encrypt_oaep(msg, public)
pt = decrypt_oaep(ct, private)
print(f"Mensaje:      {msg!r}")
print(f"Criptograma:  {len(ct)} bytes, {ct.hex()[:32]}...")
print(f"Descifrado:   {pt!r}")
print(f"Coincide: {pt == msg}")

# 3. Firma PSS y verificacion
print("\n=== 3. Firma PSS (SHA-256) ===")
doc = b"Transferir 100 Bs a la cuenta 12345"
sig = sign(doc, private)
print(f"Firma: {len(sig)} bytes, {sig.hex()[:32]}...")
print(f"verify(original) = {verify(doc, sig, public)}")

# 4. Mensaje alterado
print("\n=== 4. Mensaje alterado ===")
doc_mal = b"Transferir 900 Bs a la cuenta 12345"
print(f"Mensaje: {doc_mal!r}")
print(f"verify(alterado) = {verify(doc_mal, sig, public)}")

# 5. Un bit de la firma alterado
print("\n=== 5. Firma con 1 bit alterado ===")
sig_mal = bytearray(sig)
sig_mal[len(sig) // 2] ^= 0x01
print(f"Byte {len(sig) // 2}: {sig[len(sig) // 2]:#04x} -> {sig_mal[len(sig) // 2]:#04x}")
print(f"verify(firma alterada) = {verify(doc, bytes(sig_mal), public)}")
