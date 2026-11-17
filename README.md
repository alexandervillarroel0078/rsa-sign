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

## Reglas

- No se usan `hashlib`, `cryptography`, `pycryptodome`, `sympy`, ni `pow` de 3 argumentos en `src/`.
- `hashlib` y `pow(a, b, n)` solo aparecen en `tests/` como referencia.
- La aleatoriedad proviene de `secrets` / `os.urandom`, nunca de `random`.

## Ejecutar pruebas

Desde la raiz del proyecto:

```bash
python -m unittest discover -s tests -v
```
