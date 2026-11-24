# Manual de despliegue - RSA-Sign

Guía paso a paso para instalar, verificar y usar RSA-Sign en Windows, Linux y macOS.

> Las salidas que aparecen abajo son **reales**: se ejecutaron en Windows 11 (PowerShell
> 5.1, Python 3.10.11, AMD Ryzen 5 7535HS). Los valores aleatorios (módulos, huellas,
> firmas y tiempos) cambian en cada ejecución. En Linux y macOS los comandos son los mismos
> cambiando `python` por `python3`; esas plataformas **no se probaron** para este manual.

## 1. Requisitos

| Requisito | Detalle |
| :--- | :--- |
| Python | 3.10 o superior. No hace falta ninguna librería externa (`pip install` no es necesario). |
| Git | Para clonar el repositorio (o descargue el ZIP desde GitHub). |
| tkinter | Solo para la interfaz gráfica. Incluido en Python para Windows y macOS (python.org). En Debian/Ubuntu: `sudo apt install python3-tk`. En Fedora: `sudo dnf install python3-tkinter`. |
| Espacio | Menos de 1 MB. |

Instalar Python:

- **Windows**: <https://www.python.org/downloads/>. Marque **"Add python.exe to PATH"** en el instalador.
- **Linux**: normalmente ya viene instalado (`python3 --version`). Si no: `sudo apt install python3`.
- **macOS**: instalador de python.org o `brew install python`.

## 2. Clonar el repositorio

```bash
git clone https://github.com/alexandervillarroel0078/rsa-sign.git
cd rsa-sign
```

## 3. Verificar la instalación

**Windows (PowerShell):**

```text
PS> python --version
Python 3.10.11

PS> python -c "import tkinter; print('tkinter OK')"
tkinter OK
```

**Linux / macOS:**

```bash
python3 --version
python3 -c "import tkinter; print('tkinter OK')"
```

Ejecute las pruebas: todas deben terminar en `OK`.

```text
PS> python -m unittest discover -s tests
(una línea de puntos, un punto por test; "s" = omitido)
----------------------------------------------------------------------
Ran 160 tests in 30.404s

OK (skipped=3)
```

(Tests omitidos: dos de 2048 bits, desactivados para que la suite sea rápida, y uno de
permisos POSIX `0o600`, que en Windows no aplica y sí corre en Linux/macOS. Ningún test pide
contraseña por teclado.)

## 4. Demo rápida

```text
PS> python demo.py
=== 1. Generacion de claves ===
Tiempo: 0.160 s
Tamano de n: 1024 bits (128 bytes)
e = 65537
n = 0xba8fce5d87623f3c8182d3ba9c34e81b...

=== 2. Cifrado OAEP ===
Mensaje:      b'Hola Grupo D, mensaje secreto de prueba'
Criptograma:  128 bytes, 5c5f0318962ead7e015aac95c0e7e222...
Descifrado:   b'Hola Grupo D, mensaje secreto de prueba'
Coincide: True

=== 3. Firma PSS (SHA-256) ===
Firma: 128 bytes, 7e8d74388faeb56b738513501e3e25e7...
verify(original) = True

=== 4. Mensaje alterado ===
Mensaje: b'Transferir 900 Bs a la cuenta 12345'
verify(alterado) = False

=== 5. Firma con 1 bit alterado ===
Byte 64: 0x6e -> 0x6f
verify(firma alterada) = False
```

## 5. Generar claves

`keygen` pide la contraseña **dos veces** (no se ve al escribir) y guarda la clave privada
cifrada:

```text
PS> python cli.py keygen --bits 2048 --pub clave_publica.json --priv clave_privada.json
Contrasena de la clave privada:
Repita la contrasena:
```

> Este modo interactivo no se pudo capturar en este manual: la herramienta que ejecutó los
> comandos no tiene terminal. Las salidas siguientes usan `--pass-env`, que lee la
> contraseña de una variable de entorno y produce el mismo archivo.

```text
PS> $env:RSA_SIGN_PW = "Una frase larga de prueba 2026"
PS> python cli.py keygen --bits 2048 --pub clave_publica.json --priv clave_privada.json --pass-env RSA_SIGN_PW
[*] Generando par de claves RSA de 2048 bits...
[+] Claves generadas exitosamente.
    Modulo n: 0xca04cf9f001fe9bb45815702137539... (2048 bits)
    Exponente e: 65537
    Huella SHA-256 de la clave publica: 7ea86637d07ff3f06b6e93dd0957a822eb010152dd81bf9c49b25c63e72ac1c1
[+] Clave publica guardada en: clave_publica.json
[*] Cifrando la clave privada (PBKDF2-HMAC-SHA256)...
[+] Clave privada guardada en: clave_privada.json
```

En Linux/macOS: `export RSA_SIGN_PW="Una frase larga de prueba 2026"`.

El archivo de la clave privada no contiene `d` en claro (líneas largas recortadas aquí):

```text
PS> Get-Content clave_privada.json
{
  "version": "rsa-sign-encrypted-key-v1",
  "kdf": "pbkdf2-hmac-sha256",
  "iterations": 4000,
  "salt": "7f7cdf84e9b1f4497e8dbab4cbe882eb",
  "cipher": "hmac-sha256-ctr",
  "mac": "hmac-sha256",
  "nonce": "6f15493af8f3c8d5db2f6100da3a6fd0",
  "ciphertext": "fb08d2c6d114198d47f1c12f4a69700d3b4aba186698cc5c27d6eef976c7f97d71bf01133...
  "tag": "0cb5801a08dca597490c9384920581f630856533df64ba4f3c0bab8ecfbb2491"
}
```

- Tamaños admitidos: 1024, 2048 (recomendado), 3072 y 4096 bits. Con 4096 bits la
  generación tarda de 5 a 12 s (ver el benchmark).
- Cifrar o desbloquear la clave tarda cerca de 1,2 s: son 4000 iteraciones de
  PBKDF2-HMAC-SHA256 en Python puro.
- Dentro del cifrado va la clave completa con los parámetros CRT (`n, e, d, p, q, dP, dQ, qInv`).
- La **huella** sirve para comprobar por teléfono o en persona que el receptor tiene la
  clave pública correcta.
- **Si olvida la contraseña, la clave no se puede recuperar.** No suba las claves a Git
  (`.gitignore` ya excluye `clave_*`).
- Para pruebas: `--insecure-plain` guarda la clave **sin cifrar** y muestra un aviso.

## 6. Firmar y verificar

Cree un documento (en PowerShell):

```powershell
Set-Content -Path contrato.txt -Value "Contrato: pagar 100 Bs a la cuenta 12345" -Encoding utf8
```

En Linux/macOS: `echo "Contrato: pagar 100 Bs a la cuenta 12345" > contrato.txt`

`sign` pide la contraseña de la clave privada; aquí se pasa con `--pass-env`. `verify` usa
solo la clave pública y no pide contraseña.

```text
PS> python cli.py sign --key clave_privada.json --file contrato.txt --out contrato.sig --pass-env RSA_SIGN_PW
[+] Firma guardada en: contrato.sig

PS> python cli.py verify --key clave_publica.json --file contrato.txt --sig-file contrato.sig
    Huella SHA-256 de la clave publica: 7ea86637d07ff3f06b6e93dd0957a822eb010152dd81bf9c49b25c63e72ac1c1
[+] VERIFICACION EXITOSA: La firma es autentica e integra.
```

Si se cambia el documento (100 Bs pasa a 900 Bs), la verificación falla con código de salida 1:

```text
PS> Set-Content -Path contrato.txt -Value "Contrato: pagar 900 Bs a la cuenta 12345" -Encoding utf8
PS> python cli.py verify --key clave_publica.json --file contrato.txt --sig-file contrato.sig
    Huella SHA-256 de la clave publica: 7ea86637d07ff3f06b6e93dd0957a822eb010152dd81bf9c49b25c63e72ac1c1
[-] VERIFICACION FALLIDA: La firma es invalida o el mensaje fue adulterado.
```

También se puede firmar texto directamente: `--msg "texto"` (se admite `--msg ""`). Los
archivos se resumen por bloques, así que su tamaño no limita la memoria; con el SHA-256 en
Python puro cuente unos 3 s por MiB.

## 7. Cifrar y descifrar

```text
PS> python cli.py encrypt --key clave_publica.json --msg "mensaje secreto del Grupo D" --out mensaje.hex
    Huella SHA-256 de la clave publica: 7ea86637d07ff3f06b6e93dd0957a822eb010152dd81bf9c49b25c63e72ac1c1
[+] Criptograma guardado en: mensaje.hex

PS> python cli.py decrypt --key clave_privada.json --file mensaje.hex --pass-env RSA_SIGN_PW
[+] Mensaje descifrado: mensaje secreto del Grupo D
```

Con una contraseña incorrecta, o si el archivo de clave fue modificado (aunque sea 1 bit), el
error es el mismo:

```text
PS> $env:RSA_SIGN_PW = "contrasena equivocada"
PS> python cli.py decrypt --key clave_privada.json --file mensaje.hex --pass-env RSA_SIGN_PW
[-] Contrasena incorrecta o archivo de clave alterado.
```

Sin terminal interactiva (por ejemplo, desde un script) y sin `--pass-env`, la CLI no se
queda esperando:

```text
PS> python cli.py sign --key clave_privada.json --msg hola
[-] La clave privada requiere contrasena y no hay terminal interactiva: use --pass-env VAR.
```

OAEP-SHA256 cifra como máximo `k - 66` bytes (190 bytes con 2048 bits):

```text
PS> python cli.py encrypt --key clave_publica.json --msg <500 letras A>
    Huella SHA-256 de la clave publica: 7ea86637d07ff3f06b6e93dd0957a822eb010152dd81bf9c49b25c63e72ac1c1
[-] Error: Mensaje demasiado largo para OAEP-SHA256: 500 > 190 bytes.
```

### Claves del formato antiguo

Un archivo de clave privada antiguo `{"n": ..., "d": ...}` se sigue aceptando (sin
contraseña y sin CRT), con un aviso:

```text
PS> python cli.py sign --key clave_antigua.json --msg hola
[!] Clave privada en formato antiguo {n, d}: no incluye p ni q, se usa sin CRT. Genere un par nuevo (keygen) para tener CRT y la clave cifrada con contrasena.
[+] Firma RSA-PSS (hex): 1ca401619c441c58112b0717c7309111357b57bc96f4bb134d51a81f0e6dda75...
```

## 8. Demostraciones de ataque

**Factorización de Fermat** contra una clave con primos consecutivos (solo demostración):

```text
PS> python cli.py attack-fermat --generate-weak --bits 1024
[!] SOLO DEMOSTRACION: ataque contra claves con primos cercanos.
[*] Generando clave debil vulnerable de 1024 bits...
[+] Clave debil creada con exito.
[*] Iniciando ataque de factorizacion de Fermat sobre modulo n...
    n = 1747380226880762852368722382447197491999846060665796469337547356122604109864277224...
    e = 65537
[+] ATAQUE EXITOSO en 1 iteraciones!
    p recuperado: 1321885103509666929467228440146300930936466054199792076005658219019812222471...
    q recuperado: 1321885103509666929467228440146300930936466054199792076005658219019812222471...
    d recuperado: 1604309254797173834473326433529614115554919164995676325686399468472057187461...
```

(Números recortados aquí; la salida real los muestra completos.) Con una clave normal
generada por `keygen` el ataque no prospera, porque se exige `|p - q| > 2^(bits/2 - 100)`.

**Firma falsa con e = 1**, rechazada por la validación de claves públicas:

```text
PS> python cli.py demo-ataque e1
[!] RSA textbook / claves debiles: SOLO DEMOSTRACION, INSEGURO.
[*] Clave publica falsa con e = 1: s^1 = s, la firma falsa cuadra matematicamente: True
[+] verify la acepta: False
[+] Motivo del rechazo: Clave publica invalida: e debe ser impar y cumplir 3 <= e < n.
```

**Timing: con y sin CRT, y dependencia del exponente:**

```text
PS> python cli.py demo-ataque timing
[*] Operacion privada c^d mod n, 2048 bits, media de 10 repeticiones:
    sin CRT:    27.14 ms
    con CRT:     8.98 ms   (speedup 3.02x)
[*] Cuadrar y multiplicar depende de los bits del exponente:
    exponente con 2 bits a 1:        16.12 ms
    exponente con todos los bits:    36.41 ms
    Defensa: blinding (c' = c * r^e) aleatoriza la base en cada operacion.
```

Otras: `python cli.py demo-ataque maleabilidad`, `python cli.py demo-ataque e-pequeno`,
`python cli.py demo-ataque oraculo` y `python cli.py corrupt --hex 0011 --bit 0`.

## 9. Interfaz gráfica

```bash
python gui.py
```

1. Pestaña **1. Claves RSA**: elija el tamaño y pulse *Generar Nuevas Claves*. La barra de
   progreso se mueve mientras se buscan los primos. Se muestran la clave pública y su huella;
   la privada **no se muestra**. *Guardar Clave Privada* pide la contraseña dos veces y guarda
   el archivo cifrado; *Cargar Clave Privada* la pide si el archivo está cifrado.
2. Pestañas **2 y 3**: cifrar y descifrar con OAEP (etiqueta opcional).
3. Pestaña **4**: firmar con PSS; muestra el hash SHA-256 y la firma en hexadecimal.
4. Pestaña **5**: verificar, alterar 1 bit (firma o mensaje) y ataque de Fermat.

El nombre del texto de ejemplo se toma del archivo `AUTORES` (primera línea que no sea
comentario).

## 10. Benchmark

```text
PS> python benchmark.py --bits 1024 --iterations 10 --keygen-iterations 3 --no-sha --no-save --quiet
+--------------------------+----------------------------+
| Operacion                | 1024 bits (media / ops/s)  |
+--------------------------+----------------------------+
| Generacion Claves        |   118.447 ms (8.4 op/s)    |
| Cifrado OAEP             |   1.000 ms (999.9 op/s)    |
| Descifrado OAEP          |   2.768 ms (361.2 op/s)    |
| Descifrado OAEP sin CRT  |   5.303 ms (188.6 op/s)    |
| Firma PSS                |   2.770 ms (361.0 op/s)    |
| Firma PSS sin CRT        |   5.315 ms (188.1 op/s)    |
| Verificacion PSS         |  974.64 us (1026.0 op/s)   |
+--------------------------+----------------------------+
```

Las filas "sin CRT" usan la misma clave sin `p` y `q`; la diferencia es la aceleración del
CRT. `python benchmark.py` sin opciones mide 1024, 2048, 3072 y 4096 bits más SHA-256 (unos 3 a
5 minutos) y reescribe `BENCHMARK_RESULTADOS.md` y `BENCHMARK_RESULTADOS.csv`. No use el
equipo para otras tareas mientras corre: altera los tiempos.

## 11. Solución de problemas

| Síntoma | Causa y solución |
| :--- | :--- |
| `'python' no se reconoce como un comando` (Windows) | Python no está en el PATH. Reinstale marcando "Add python.exe to PATH" o use `py` en lugar de `python`. |
| `python` abre la Microsoft Store | Desactive los "Alias de ejecución de aplicaciones" de Python en Configuración de Windows, o use `py`. |
| `ModuleNotFoundError: No module named 'src'` | Aparece con `python -m src.cli` o con los tests fuera de la raíz. Ejecútelos desde la carpeta raíz del proyecto (donde están `cli.py` y `src/`). `python cli.py` funciona desde cualquier carpeta si se da la ruta. |
| `ModuleNotFoundError: No module named 'tkinter'` | Instale tkinter (ver Requisitos). La CLI funciona sin tkinter. |
| `[-] Error: Clave publica debil: n tiene 512 bits...` | Las claves públicas de menos de 1024 bits se rechazan. Genere una de 2048. |
| `[-] Error: Mensaje demasiado largo para OAEP-SHA256` | OAEP cifra mensajes cortos (≤ `k - 66` bytes). Use una clave más grande o un mensaje más corto. |
| `[-] Contrasena incorrecta o archivo de clave alterado.` | La contraseña no es la correcta o el archivo `.json` de la clave privada se modificó. Son indistinguibles a propósito. Si olvidó la contraseña, la clave no se puede recuperar: genere un par nuevo. |
| `[-] La clave privada requiere contrasena y no hay terminal interactiva` | Está ejecutando desde un script o una tubería. Pase la contraseña con `--pass-env VAR`. |
| `[!] Clave privada en formato antiguo {n, d}` | Archivo creado con la versión anterior. Funciona, pero sin CRT ni cifrado; genere un par nuevo con `keygen`. |
| Desbloquear la clave tarda ~1 s | Es intencional: 4000 iteraciones de PBKDF2 para frenar la prueba de contraseñas. |
| `[-] Error de descifrado: decryption error` | Clave privada incorrecta, etiqueta distinta o criptograma alterado. El mensaje es único a propósito: no revela la causa. |
| `[-] VERIFICACION FALLIDA` | El documento o la firma cambiaron, o la clave pública no es la del firmante (compare la huella). |
| Caracteres raros (tildes) en la consola de Windows | Ejecute `chcp 65001` o defina `$env:PYTHONIOENCODING="utf-8"`. |
| Tests lentos o muy variables | Es Python puro; cierre otros programas. La suite tarda unos 25 s. |
| La GUI no abre en Linux por SSH | Necesita un entorno gráfico (`$DISPLAY`). Use la CLI. |
