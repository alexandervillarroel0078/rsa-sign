# RSA-Sign

Sistema de firma digital RSA con generador de primos Miller-Rabin y hash SHA-256,
implementado desde cero en Python (Proyecto 2, ELC107 Criptografía y Seguridad,
UAGRM - FICCT, Grupo D).

Todo el motor criptográfico (SHA-256, aritmética modular, Miller-Rabin, generación de
claves, OAEP y PSS) está escrito a mano. En `src/` no se usan `hashlib`, `hmac`,
`pow(a, b, n)` ni librerías criptográficas: solo la biblioteca estándar de Python
(`secrets` como fuente de aleatoriedad).

## Integrantes

| Nombre | Registro | Usuario de GitHub |
| :--- | :--- | :--- |
| <<COMPLETAR>> | <<COMPLETAR>> | <<COMPLETAR>> |
| <<COMPLETAR>> | <<COMPLETAR>> | <<COMPLETAR>> |

Docente: <<COMPLETAR>>. Semestre: <<COMPLETAR>>.

## Requisitos

- Python 3.10 o superior (probado con 3.10.11 en Windows 11).
- Ninguna dependencia externa: no hace falta `pip install`.
- Opcional: `tkinter` para la interfaz gráfica (viene con Python en Windows y macOS;
  en Debian/Ubuntu: `sudo apt install python3-tk`).

## Instalación rápida

```bash
git clone https://github.com/alexandervillarroel0078/rsa-sign.git
cd rsa-sign
python -m unittest discover -s tests
python demo.py
```

En Linux/macOS use `python3` si `python` apunta a Python 2. El
[MANUAL_DESPLIEGUE.md](MANUAL_DESPLIEGUE.md) tiene la guía paso a paso con salidas reales.

## Uso

### Demo en 10 segundos

```bash
python demo.py
```

Genera una clave de 1024 bits, cifra y descifra con OAEP, firma con PSS y muestra que la
verificación falla al alterar el mensaje o 1 bit de la firma.

### Línea de comandos

Las tres formas son equivalentes: `python cli.py ...`, `python -m src.cli ...` y
`python src/cli.py ...`. Ayuda de cada subcomando: `python cli.py <subcomando> --help`.

```bash
# Claves (1024, 2048, 3072 o 4096 bits; por defecto 2048).
# Pide la contraseña dos veces (no se ve al escribir) y guarda la privada CIFRADA.
python cli.py keygen --bits 2048 --pub clave_publica.json --priv clave_privada.json

# Firmar y verificar (texto con --msg o archivo con --file, que se lee por bloques).
# sign y decrypt piden la contraseña de la clave privada.
python cli.py sign   --key clave_privada.json --file contrato.txt --out contrato.sig
python cli.py verify --key clave_publica.json --file contrato.txt --sig-file contrato.sig

# Cifrar y descifrar con RSA-OAEP (máximo k - 66 bytes: 190 bytes con 2048 bits)
python cli.py encrypt --key clave_publica.json --msg "mensaje secreto" --out mensaje.hex
python cli.py decrypt --key clave_privada.json --file mensaje.hex

# Demostraciones de ataque (SOLO DEMOSTRACION)
python cli.py attack-fermat --generate-weak --bits 1024
python cli.py corrupt --hex 0011223344 --bit 0
python cli.py demo-ataque maleabilidad   # RSA textbook es maleable y determinista
python cli.py demo-ataque e-pequeno      # e = 3 sin relleno: raíz cúbica
python cli.py demo-ataque e1             # firma falsa con e = 1: rechazada
python cli.py demo-ataque oraculo        # OAEP: un único mensaje de error
python cli.py demo-ataque timing         # con/sin CRT y dependencia del exponente
```

Al generar o cargar una clave pública se muestra su **huella SHA-256** (de `n || e`),
para comprobar por un canal aparte que ambas partes tienen la misma clave.

**Contraseña sin interacción** (scripts, tareas programadas): `--pass-env VAR` lee la
contraseña de la variable de entorno `VAR`. Es menos seguro que escribirla, porque otros
procesos del mismo usuario pueden leer el entorno.

```powershell
$env:RSA_SIGN_PW = "una frase larga"        # Linux/macOS: export RSA_SIGN_PW="una frase larga"
python cli.py sign --key clave_privada.json --msg hola --pass-env RSA_SIGN_PW
```

`--insecure-plain` (solo en `keygen`) guarda la clave privada **sin cifrar**; es únicamente
para pruebas y demostraciones.

### Formato de los archivos de clave

| Archivo | Contenido |
| :--- | :--- |
| Clave pública | JSON `{"n": "0x...", "e": "0x..."}` |
| Clave privada cifrada (por defecto) | JSON `{"version": "rsa-sign-encrypted-key-v1", "kdf": "pbkdf2-hmac-sha256", "iterations": 4000, "salt", "cipher": "hmac-sha256-ctr", "mac": "hmac-sha256", "nonce", "ciphertext", "tag"}` (binarios en hex) |
| Clave privada sin cifrar (`--insecure-plain`) | JSON v2 `{"format": "rsa-sign-private-v2", "n", "e", "d", "p", "q", "dp", "dq", "qinv"}` |
| Clave privada antigua | JSON `{"n", "d"}`: se sigue aceptando, con un aviso, pero sin CRT (no tiene `p` ni `q`) |

El texto cifrado contiene el JSON v2. Cifrado de la clave (módulo `src/kdf_mac.py`, todo
sobre el SHA-256 propio):

1. `maestra = PBKDF2-HMAC-SHA256(contraseña, salt de 16 bytes, iteraciones, 32 bytes)`
2. `k_enc = HMAC(maestra, "rsa-sign/enc")`, `k_mac = HMAC(maestra, "rsa-sign/mac")`
3. Flujo en modo contador: `HMAC(k_enc, nonce || 0) || HMAC(k_enc, nonce || 1) || ...`;
   `ciphertext = JSON v2 XOR flujo`
4. `tag = HMAC(k_mac, cabecera || nonce || ciphertext)` (encrypt-then-MAC; la cabecera incluye
   formato, iteraciones y salt)

Al cargar, primero se comprueba la etiqueta (comparación sin salida temprana) y solo después
se descifra. Una contraseña incorrecta o cualquier byte alterado dan el mismo error. Los
archivos de clave privada se crean con permisos `0o600` (en Windows rigen las ACL de la
carpeta del usuario).

Los errores (archivo inexistente, hexadecimal inválido, clave débil, mensaje demasiado
largo) se informan en una línea `[-] ...` con código de salida 1, sin traceback.

### Interfaz gráfica

```bash
python gui.py
```

Cinco pestañas: claves, cifrado OAEP, descifrado OAEP, firma PSS y verificación con
demostraciones de ataque (alteración de 1 bit y Fermat). La generación de claves corre en un
hilo aparte y no congela la ventana. La clave privada nunca se muestra en pantalla: solo la
pública y su huella. Al guardarla se pide la contraseña dos veces, y al cargar una clave
cifrada se pide de nuevo. El nombre del texto de ejemplo se lee del archivo
[AUTORES](AUTORES).

### Pruebas

```bash
python -m unittest discover -s tests -v
```

`hashlib`, `hmac` y `pow(a, b, n)` solo aparecen en `tests/` como referencia para comparar
resultados.

### Benchmark

```bash
python benchmark.py                          # 1024-4096 bits, escribe BENCHMARK_RESULTADOS.md y .csv
python benchmark.py --bits 1024 2048 --no-save --markdown
```

Resultados medidos: [BENCHMARK_RESULTADOS.md](BENCHMARK_RESULTADOS.md).

## Estructura

| Módulo | Responsabilidad |
| :--- | :--- |
| `src/sha256.py` | SHA-256 según FIPS 180-4: relleno, calendario, 64 rondas. Versión incremental (`Sha256`) y por archivo (`sha256_file`). |
| `src/mathcore.py` | `gcd`, Euclides extendido (`egcd`), inverso modular (`modinv`), exponenciación modular por cuadrar y multiplicar (`modexp`). |
| `src/primes.py` | Criba de Eratóstenes, Miller-Rabin (`is_probable_prime`) y generación de primos (`generate_prime`). |
| `src/oaep.py` | MGF1-SHA256 y relleno OAEP (RFC 8017) con decodificación sin salidas tempranas. |
| `src/pss.py` | Relleno de firma EMSA-PSS-SHA256 (RFC 8017). |
| `src/kdf_mac.py` | HMAC-SHA256 (RFC 2104/4231), PBKDF2-HMAC-SHA256 (RFC 8018) y cifrado autenticado de la clave privada. |
| `src/rsa.py` | Generación de claves (`RSAPrivateKey` con CRT), operación privada con CRT y blinding, validación de claves públicas, huella, cifrado/descifrado OAEP, firma/verificación PSS, persistencia en JSON (cifrada), RSA textbook (solo demostración). |
| `src/attacks.py` | Ataque de Fermat, clave débil, alteración de 1 bit y demostraciones (maleabilidad, e pequeño, e = 1, oráculo OAEP). |
| `src/cli.py`, `src/gui.py` | Interfaces de línea de comandos y gráfica. |
| `src/benchmark.py` | Medición de rendimiento y generación del informe. |
| `cli.py`, `gui.py`, `demo.py`, `benchmark.py` | Puntos de entrada en la raíz. |
| `tests/` | Pruebas unitarias e integración (`unittest`). |

## Decisiones de diseño

- **Miller-Rabin con 40 rondas** y bases aleatorias de `secrets`, precedido de división de
  prueba por los primos menores que 1000. Probabilidad de aceptar un compuesto ≤ 4⁻⁴⁰ = 2⁻⁸⁰.
- **Primos**: candidatos de `secrets.randbits` con los dos bits altos y el bit bajo forzados;
  así `n = p·q` tiene exactamente los bits pedidos. Se exige `gcd(e, p-1) = gcd(e, q-1) = 1`
  y `|p - q| > 2^(bits/2 - 100)` (FIPS 186-4) para resistir la factorización de Fermat.
- **e = 65537** y `d = e⁻¹ mod φ(n)` con el algoritmo extendido de Euclides.
- **OAEP-SHA256** para cifrar (aleatorio y no maleable) y **PSS-SHA256** con salt de 32 bytes
  para firmar (RFC 8017). El RSA "textbook" se conserva solo para demostrar sus ataques.
- **Zero-Trust**: toda clave pública se valida antes de usarse (`n` impar, `e` impar con
  `3 ≤ e < n`, `n ≥ 1024` bits). Esto bloquea, por ejemplo, la falsificación de firmas con
  `e = 1`.
- **Sin oráculo de relleno**: cualquier fallo de descifrado da el mismo
  `ValueError("decryption error")`, y la decodificación OAEP recorre todo el bloque antes de
  decidir.
- **CRT (Teorema Chino del Resto) con recombinación de Garner**: la clave privada guarda
  `p, q, dP = d mod (p-1), dQ = d mod (q-1), qInv = q⁻¹ mod p` (calculado con el AEE).
  Descifrado y firma hacen `m1 = c^dP mod p`, `m2 = c^dQ mod q`, `h = qInv·(m1 - m2) mod p`,
  `m = m2 + h·q`. Medido: de 2 a 3,2 veces más rápido según el tamaño (ver benchmark).
- **Blinding**: antes de la operación privada se toma `r` aleatorio y se opera sobre
  `c·r^e mod n`; el resultado se multiplica por `r⁻¹`. El tiempo deja de depender del valor
  que elige el atacante (contramedida contra ataques de temporización).
- **Protección contra fallos**: tras firmar se comprueba `s^e mod n = EM` antes de entregar la
  firma. Una firma CRT defectuosa permitiría factorizar `n` (ataque de Bellcore).
- **Clave privada cifrada en disco** con PBKDF2-HMAC-SHA256 y encrypt-then-MAC (ver Formato de
  los archivos de clave).

## Limitaciones conocidas

- **Tiempo constante**: los enteros de Python no garantizan operaciones de tiempo constante.
  La exponenciación modular depende de los bits del exponente (lo muestra
  `python cli.py demo-ataque timing`). El blinding y las comparaciones por acumulación XOR
  eliminan las dependencias gruesas, no las microarquitectónicas.
- **Rendimiento**: SHA-256 en Python puro procesa del orden de 0,3 MiB/s (ver benchmark);
  firmar un archivo de cientos de MB tarda minutos.
- **Iteraciones de PBKDF2**: se usan **4000** para que desbloquear la clave tarde de 1 a 2 s
  (medido: 1,24 s en promedio con un Ryzen 5 7535HS). OWASP recomienda 600 000 para
  PBKDF2-HMAC-SHA256, unas 150 veces más; en Python puro tardaría de 3 a 5 minutos. Con 4000
  iteraciones la protección frente a un atacante que roba el archivo y prueba contraseñas
  con GPU es **baja**: use una frase de contraseña larga. El número se guarda en cada archivo
  y puede subirse sin romper los existentes.
- **Memoria**: la contraseña, las claves derivadas y el flujo de cifrado se guardan en
  `bytearray` y se sobrescriben con ceros al terminar. Pero los `int` de Python son
  inmutables: `d`, `p`, `q` y los valores intermedios de SHA-256 no se pueden borrar de forma
  garantizada, y quedan en memoria hasta que el recolector los libera. La GUI recibe la
  contraseña de tkinter como `str`, que tampoco se puede borrar.
- **Clave antigua `{n, d}`**: se acepta, pero sin CRT; el blinding solo se activa si se
  comprueba que `e = 65537` corresponde a `d`.
- **OAEP** cifra mensajes cortos (como máximo `k - 66` bytes). No hay modo híbrido.

## Mejoras futuras

- Modo híbrido: clave de sesión cifrada con RSA-OAEP y datos con AES-GCM (o con un cifrado
  simétrico más HMAC).
- Criptografía de curva elíptica (ECDSA / Ed25519) para claves y firmas más cortas.
- Exportación a PEM/DER para interoperar con OpenSSL.
