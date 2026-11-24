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
Ran 123 tests in 24.501s

OK (skipped=2)
```

(Los 2 tests omitidos son los de 2048 bits, que están desactivados para que la suite sea
rápida.)

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

```text
PS> python cli.py keygen --bits 2048 --pub clave_publica.json --priv clave_privada.json
[*] Generando par de claves RSA de 2048 bits...
[+] Claves generadas exitosamente.
    Modulo n: 0xc79fb4cd0a48524fa474b02dadc823... (2048 bits)
    Exponente e: 65537
    Huella SHA-256 de la clave publica: 0e55f91105d822193f6ca7d543b82d65653284b892185598f57d969b344b6c1b
[+] Clave publica guardada en: clave_publica.json
[+] Clave privada guardada en: clave_privada.json
```

- Tamaños admitidos: 1024, 2048 (recomendado), 3072 y 4096 bits. Con 4096 bits la
  generación tarda unos 10 s en promedio (ver el benchmark).
- La **huella** sirve para comprobar por teléfono o en persona que el receptor tiene la
  clave pública correcta.
- `clave_privada.json` contiene `d` **sin cifrar**: no lo comparta ni lo suba a Git
  (`.gitignore` ya excluye `clave_*`).

## 6. Firmar y verificar

Cree un documento (en PowerShell):

```powershell
Set-Content -Path contrato.txt -Value "Contrato: pagar 100 Bs a la cuenta 12345" -Encoding utf8
```

En Linux/macOS: `echo "Contrato: pagar 100 Bs a la cuenta 12345" > contrato.txt`

```text
PS> python cli.py sign --key clave_privada.json --file contrato.txt --out contrato.sig
[+] Firma guardada en: contrato.sig

PS> python cli.py verify --key clave_publica.json --file contrato.txt --sig-file contrato.sig
    Huella SHA-256 de la clave publica: 0e55f91105d822193f6ca7d543b82d65653284b892185598f57d969b344b6c1b
[+] VERIFICACION EXITOSA: La firma es autentica e integra.
```

Si se cambia el documento (100 Bs pasa a 900 Bs), la verificación falla con código de salida 1:

```text
PS> Set-Content -Path contrato.txt -Value "Contrato: pagar 900 Bs a la cuenta 12345" -Encoding utf8
PS> python cli.py verify --key clave_publica.json --file contrato.txt --sig-file contrato.sig
    Huella SHA-256 de la clave publica: 0e55f91105d822193f6ca7d543b82d65653284b892185598f57d969b344b6c1b
[-] VERIFICACION FALLIDA: La firma es invalida o el mensaje fue adulterado.
```

También se puede firmar texto directamente: `--msg "texto"` (se admite `--msg ""`). Los
archivos se resumen por bloques, así que su tamaño no limita la memoria; con el SHA-256 en
Python puro cuente unos 2,5 s por MiB.

## 7. Cifrar y descifrar

```text
PS> python cli.py encrypt --key clave_publica.json --msg "mensaje secreto del Grupo D" --out mensaje.hex
    Huella SHA-256 de la clave publica: 0e55f91105d822193f6ca7d543b82d65653284b892185598f57d969b344b6c1b
[+] Criptograma guardado en: mensaje.hex

PS> python cli.py decrypt --key clave_privada.json --file mensaje.hex
[+] Mensaje descifrado: mensaje secreto del Grupo D
```

OAEP-SHA256 cifra como máximo `k - 66` bytes (190 bytes con 2048 bits):

```text
PS> python cli.py encrypt --key clave_publica.json --msg <500 letras A>
    Huella SHA-256 de la clave publica: 0e55f91105d822193f6ca7d543b82d65653284b892185598f57d969b344b6c1b
[-] Error: Mensaje demasiado largo para OAEP-SHA256: 500 > 190 bytes.
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

Otras: `python cli.py demo-ataque maleabilidad`, `python cli.py demo-ataque e-pequeno`,
`python cli.py demo-ataque oraculo` y `python cli.py corrupt --hex 0011 --bit 0`.

## 9. Interfaz gráfica

```bash
python gui.py
```

1. Pestaña **1. Claves RSA**: elija el tamaño y pulse *Generar Nuevas Claves*. La barra de
   progreso se mueve mientras se buscan los primos. Guarde o cargue las claves en `.json`.
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
| Generacion Claves        |   103.022 ms (9.7 op/s)    |
| Cifrado OAEP             |   1.121 ms (891.8 op/s)    |
| Descifrado OAEP          |   5.527 ms (180.9 op/s)    |
| Firma PSS                |   5.210 ms (192.0 op/s)    |
| Verificacion PSS         |   1.076 ms (929.6 op/s)    |
+--------------------------+----------------------------+
```

`python benchmark.py` sin opciones mide 1024, 2048, 3072 y 4096 bits más SHA-256 (unos 3 a
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
| `[-] Error de descifrado: decryption error` | Clave privada incorrecta, etiqueta distinta o criptograma alterado. El mensaje es único a propósito: no revela la causa. |
| `[-] VERIFICACION FALLIDA` | El documento o la firma cambiaron, o la clave pública no es la del firmante (compare la huella). |
| Caracteres raros (tildes) en la consola de Windows | Ejecute `chcp 65001` o defina `$env:PYTHONIOENCODING="utf-8"`. |
| Tests lentos o muy variables | Es Python puro; cierre otros programas. La suite tarda unos 25 s. |
| La GUI no abre en Linux por SSH | Necesita un entorno gráfico (`$DISPLAY`). Use la CLI. |
