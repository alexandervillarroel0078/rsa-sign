# rsa-sign

Primitivas criptograficas implementadas a mano en Python 3.11+, sin dependencias externas en la logica.

## Modulos

- `src/sha256.py`: SHA-256 segun FIPS 180-4.
  - `sha256(data: bytes) -> bytes` (32 bytes)
  - `sha256_hex(data: bytes) -> str`
- `src/mathcore.py`: aritmetica modular.
  - `egcd(a, b) -> (g, x, y)` con `a*x + b*y == g`
  - `modinv(a, n) -> int` (lanza `ValueError` si `gcd(a, n) != 1`)
  - `modexp(base, exp, mod) -> int` (cuadrar y multiplicar)
  - `gcd(a, b) -> int`
- `src/primes.py`: generacion y test de primalidad.
  - `is_probable_prime(n, rounds=40) -> bool` (Miller-Rabin)
  - `generate_prime(bits) -> int`
- `src/rsa.py`: claves RSA y persistencia.
  - `generate_keypair(bits, e=65537) -> (pub, priv)`
  - `save_public_key`, `load_public_key`, `save_private_key`, `load_private_key`
  - `rsa_encrypt_int`, `rsa_decrypt_int`
- `src/mgf1.py`: funcion generadora de mascaras MGF1 (RFC 8017).
  - `mgf1(seed, mask_len) -> bytes`
- `src/oaep.py`: relleno y cifrado seguro OAEP (PKCS#1 v2.2).
  - `rsa_encrypt_oaep(message, pub_key, label=b"") -> bytes`
  - `rsa_decrypt_oaep(ciphertext, priv_key, label=b"") -> bytes`
- `src/pss.py`: esquema de firma digital PSS y verificacion en tiempo constante.
  - `rsa_sign_pss(message, priv_key, s_len=32) -> bytes`
  - `rsa_verify_pss(message, signature, pub_key, s_len=32) -> bool`
  - `constant_time_compare(a, b) -> bool`
- `src/attacks.py`: analisis criptografico y ataques.
  - `isqrt(n) -> int` (raiz cuadrada entera por metodo babilonico / Newton)
  - `fermat_factor(n, max_iter) -> (p, q)`
  - `fermat_attack_rsa(pub_key, max_iter) -> (priv_key, iteraciones)`
  - `generate_weak_fermat_key(bits) -> (pub, priv)`
  - `corrupt_bit(data, bit_index) -> bytes`

## Interfaces de Usuario

- `gui.py` (`src/gui.py`): Aplicacion grafica en Tkinter con 5 pestanas:
  1. Claves RSA (generacion y archivos .pem)
  2. Cifrado OAEP
  3. Descifrado OAEP
  4. Firma PSS
  5. Verificacion y Ataques (Fermat y alteracion de 1 bit)
- `cli.py` (`src/cli.py`): CLI de respaldo con subcomandos `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `attack-fermat` y `corrupt`.

## Reglas

- No se usan `hashlib`, `cryptography`, `pycryptodome`, `sympy`, ni `pow` de 3 argumentos en `src/`.
- `hashlib` y `pow(a, b, n)` solo aparecen en `tests/` como referencia.
- La aleatoriedad proviene de `secrets` / `os.urandom`, nunca de `random`.

## Ejecutar pruebas

Desde la raiz del proyecto:

```bash
python3 -m unittest discover -s tests -v
```
