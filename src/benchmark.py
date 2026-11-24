"""
Evaluacion de rendimiento (benchmark) de RSA-Sign.

Mide, por tamano de clave (1024, 2048, 3072, 4096 bits):
1. Generacion de claves (Miller-Rabin, p, q, n, e, d).
2. Cifrado OAEP-SHA256.
3. Descifrado OAEP-SHA256 (con CRT y sin CRT, si la clave tiene CRT).
4. Firma PSS-SHA256 (con CRT y sin CRT, si la clave tiene CRT).
5. Verificacion PSS-SHA256.
Ademas mide el SHA-256 propio (64 B, 1 KiB, 1 MiB) y, si se le pasa una
funcion de referencia (hashlib.sha256 desde el benchmark.py de la raiz), la
compara. src/ no importa hashlib: la regla del proyecto lo prohibe aqui.

Estadisticos: media, desviacion estandar muestral, mediana, minimo y maximo.
Escribe BENCHMARK_RESULTADOS.md y BENCHMARK_RESULTADOS.csv con el hardware y
la version de Python detectados automaticamente.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence

try:
    from .rsa import RSAPrivateKey, decrypt_oaep, encrypt_oaep, generate_keypair, sign, verify
    from .sha256 import sha256
except ImportError:
    # Soporte para ejecucion directa
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.rsa import RSAPrivateKey, decrypt_oaep, encrypt_oaep, generate_keypair, sign, verify
    from src.sha256 import sha256


RAIZ = Path(__file__).resolve().parent.parent

# Tamanos estandar evaluados.
DEFAULT_BITS: tuple[int, ...] = (1024, 2048, 3072, 4096)

# Repeticiones de generacion de claves por tamano (la busqueda de primos es lenta).
DEFAULT_KEYGEN_ITERATIONS: dict[int, int] = {1024: 10, 2048: 10, 3072: 5, 4096: 5}

# Repeticiones minimas del resto de operaciones.
DEFAULT_OP_ITERATIONS: int = 10

# Tamanos de entrada para SHA-256.
SHA_SIZES: tuple[tuple[str, int], ...] = (("64 B", 64), ("1 KiB", 1024), ("1 MiB", 1024 * 1024))

# Orden de las operaciones en las tablas.
OPERATIONS: tuple[str, ...] = (
    "Generacion Claves",
    "Cifrado OAEP",
    "Descifrado OAEP",
    "Descifrado OAEP sin CRT",
    "Firma PSS",
    "Firma PSS sin CRT",
    "Verificacion PSS",
)


@dataclass
class OpStats:
    """Estadisticas de rendimiento para una operacion criptografica."""
    operation: str
    bits: int
    iterations: int
    mean_seconds: float
    std_seconds: float
    min_seconds: float
    max_seconds: float
    ops_per_second: float
    median_seconds: float = 0.0

    @staticmethod
    def _fmt(sec: float) -> str:
        if sec >= 1.0:
            return f"{sec:.3f} s"
        if sec >= 0.001:
            return f"{sec * 1000.0:.3f} ms"
        return f"{sec * 1_000_000.0:.2f} us"

    def format_mean_time(self) -> str:
        """Formatea el tiempo promedio en unidades legibles (s, ms, us)."""
        return self._fmt(self.mean_seconds)

    def format_std_time(self) -> str:
        """Formatea la desviacion estandar en unidades legibles."""
        return self._fmt(self.std_seconds)

    def format_median_time(self) -> str:
        return self._fmt(self.median_seconds)

    def format_min_time(self) -> str:
        return self._fmt(self.min_seconds)

    def format_max_time(self) -> str:
        return self._fmt(self.max_seconds)


def calculate_stats(times: Sequence[float], operation: str, bits: int) -> OpStats:
    """Calcula media, desviacion estandar muestral (n-1), mediana, min y max."""
    n = len(times)
    if n == 0:
        raise ValueError("La lista de tiempos no puede estar vacia.")

    mean = sum(times) / n
    variance = sum((x - mean) ** 2 for x in times) / (n - 1) if n > 1 else 0.0
    return OpStats(
        operation=operation,
        bits=bits,
        iterations=n,
        mean_seconds=mean,
        std_seconds=math.sqrt(variance),
        min_seconds=min(times),
        max_seconds=max(times),
        ops_per_second=(1.0 / mean) if mean > 0 else float("inf"),
        median_seconds=statistics.median(times),
    )


def time_operation(func: Callable, *args, **kwargs) -> tuple[float, any]:
    """Mide en segundos una llamada con time.perf_counter (reloj monotono)."""
    t0 = time.perf_counter()
    result = func(*args, **kwargs)
    t1 = time.perf_counter()
    return (t1 - t0, result)


def _variantes_privadas(priv) -> list[tuple[str, object]]:
    """
    Variantes de clave privada a medir: la clave tal cual y, si tiene
    parametros CRT (atributo 'p'), tambien la misma clave sin p y q, que fuerza
    la exponenciacion completa c^d mod n.
    """
    if getattr(priv, "p", None):
        # Misma clave sin p, q: conserva e, asi blinding y la comprobacion de
        # la firma se aplican igual y la unica diferencia medida es el CRT.
        sin_crt = RSAPrivateKey(priv[0], priv[1], e=priv.e)
        return [("", priv), (" sin CRT", sin_crt)]
    return [("", priv)]


def run_benchmark_for_bits(
    bits: int,
    iterations: int = 3,
    sample_message: bytes = b"Benchmark RSA-OAEP-PSS ELC107 Grupo D",
    progress_callback: Callable[[str], None] | None = None,
    keygen_iterations: int | None = None,
    compare_crt: bool = False,
) -> dict[str, OpStats]:
    """
    Ejecuta el benchmark completo para un tamano de clave.

    :param iterations: repeticiones de cada operacion (salvo keygen).
    :param keygen_iterations: repeticiones de keygen (por defecto = iterations).
    :param compare_crt: si la clave tiene CRT, mide tambien descifrado y firma sin CRT.
    :return: {operacion: OpStats}.
    """
    if bits < 528:
        raise ValueError(
            f"Tamano de clave {bits} bits insuficiente para OAEP-SHA256 "
            f"(requiere al menos 528 bits / 66 bytes)."
        )
    kg_iters = keygen_iterations if keygen_iterations else iterations

    def log(msg):
        if progress_callback:
            progress_callback(msg)

    log(f"Iniciando pruebas para {bits} bits (keygen x{kg_iters}, operaciones x{iterations})...")

    # 1. Generacion de claves
    keygen_times: list[float] = []
    keypair = None
    for i in range(kg_iters):
        log(f"[{bits}b] Generando par de claves ({i + 1}/{kg_iters})...")
        t, kp = time_operation(generate_keypair, bits)
        keygen_times.append(t)
        if keypair is None:
            keypair = kp
    pub, priv = keypair
    resultados = {"Generacion Claves": calculate_stats(keygen_times, "Generacion Claves", bits)}

    # 2. Cifrado OAEP
    tiempos, ciphertexts = [], []
    for i in range(iterations):
        t, ct = time_operation(encrypt_oaep, sample_message, pub)
        tiempos.append(t)
        ciphertexts.append(ct)
    resultados["Cifrado OAEP"] = calculate_stats(tiempos, "Cifrado OAEP", bits)
    log(f"[{bits}b] Cifrado OAEP x{iterations} listo.")

    variantes = _variantes_privadas(priv) if compare_crt else [("", priv)]

    # 3. Descifrado OAEP (con / sin CRT)
    for sufijo, clave in variantes:
        tiempos = []
        for i in range(iterations):
            t, pt = time_operation(decrypt_oaep, ciphertexts[i % len(ciphertexts)], clave)
            if pt != sample_message:
                raise RuntimeError(f"Falla de integridad: texto descifrado no coincide ({bits}b)")
            tiempos.append(t)
        nombre = "Descifrado OAEP" + sufijo
        resultados[nombre] = calculate_stats(tiempos, nombre, bits)
        log(f"[{bits}b] {nombre} x{iterations} listo.")

    # 4. Firma PSS (con / sin CRT)
    signatures = []
    for sufijo, clave in variantes:
        tiempos = []
        for i in range(iterations):
            t, sig = time_operation(sign, sample_message, clave)
            tiempos.append(t)
            signatures.append(sig)
        nombre = "Firma PSS" + sufijo
        resultados[nombre] = calculate_stats(tiempos, nombre, bits)
        log(f"[{bits}b] {nombre} x{iterations} listo.")

    # 5. Verificacion PSS
    tiempos = []
    for i in range(iterations):
        t, ok = time_operation(verify, sample_message, signatures[i % len(signatures)], pub)
        if not ok:
            raise RuntimeError(f"Falla de integridad: firma no valida en verificacion ({bits}b)")
        tiempos.append(t)
    resultados["Verificacion PSS"] = calculate_stats(tiempos, "Verificacion PSS", bits)
    log(f"[{bits}b] Verificacion PSS x{iterations} listo.")

    return resultados


def run_full_benchmark(
    bits_list: Sequence[int] = DEFAULT_BITS,
    custom_iterations: dict[int, int] | None = None,
    progress_callback: Callable[[str], None] | None = None,
    keygen_iterations: dict[int, int] | None = None,
    compare_crt: bool = True,
) -> dict[int, dict[str, OpStats]]:
    """
    Ejecuta el benchmark sobre todos los tamanos indicados.

    :param custom_iterations: {bits: repeticiones} de las operaciones (defecto 10).
    :param keygen_iterations: {bits: repeticiones} de keygen (defecto DEFAULT_KEYGEN_ITERATIONS).
    """
    results: dict[int, dict[str, OpStats]] = {}
    for bits in bits_list:
        iters = (custom_iterations or {}).get(bits, DEFAULT_OP_ITERATIONS)
        kg = (keygen_iterations or {}).get(bits, DEFAULT_KEYGEN_ITERATIONS.get(bits, iters))
        results[bits] = run_benchmark_for_bits(
            bits=bits,
            iterations=iters,
            keygen_iterations=kg,
            progress_callback=progress_callback,
            compare_crt=compare_crt,
        )
    return results


def run_sha_benchmark(
    reference: Callable[[bytes], bytes] | None = None,
    sizes: Sequence[tuple[str, int]] = SHA_SIZES,
    progress_callback: Callable[[str], None] | None = None,
) -> list[dict]:
    """
    Mide el SHA-256 propio (y la referencia, si se pasa) para varios tamanos.

    Repeticiones: 10 hasta 1 KiB y 3 para 1 MiB (cada una tarda segundos en
    Python puro). Comprueba ademas que ambos resumenes coinciden.
    """
    filas = []
    for etiqueta, size in sizes:
        data = bytes((i * 31) & 0xFF for i in range(size))
        reps = 10 if size <= 1024 else 3
        if progress_callback:
            progress_callback(f"SHA-256 {etiqueta} x{reps}...")
        propio = [time_operation(sha256, data)[0] for _ in range(reps)]
        fila = {"tamano": etiqueta, "bytes": size, "stats": calculate_stats(propio, f"SHA-256 {etiqueta}", 0)}
        if reference is not None:
            ref_reps = max(reps, 100)
            ref = [time_operation(reference, data)[0] for _ in range(ref_reps)]
            fila["ref_stats"] = calculate_stats(ref, f"Referencia {etiqueta}", 0)
            fila["coincide"] = sha256(data) == reference(data)
        filas.append(fila)
    return filas


def describe_os(system: str | None = None, version: str | None = None) -> str:
    """
    Nombre del sistema operativo. En Windows, Python 3.10 informa "Windows-10"
    tambien en Windows 11; Windows 11 se reconoce por el build >= 22000.
    """
    system = platform.system() if system is None else system
    version = platform.version() if version is None else version
    if system == "Windows":
        try:
            build = int(version.split(".")[2])
        except (IndexError, ValueError):
            return platform.platform()
        if build >= 22000:
            return f"Windows 11 (build {build})"
        return f"Windows 10 (build {build})" if version.startswith("10.") else f"Windows {version}"
    return platform.platform()


def detect_environment() -> dict[str, str]:
    """CPU, sistema operativo y version de Python detectados automaticamente."""
    cpu = ""
    try:
        if sys.platform.startswith("win"):
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                cpu = winreg.QueryValueEx(k, "ProcessorNameString")[0]
        elif sys.platform == "darwin":
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, timeout=5).stdout
        else:
            for linea in Path("/proc/cpuinfo").read_text().splitlines():
                if linea.lower().startswith("model name"):
                    cpu = linea.split(":", 1)[1]
                    break
    except Exception:
        cpu = ""
    return {
        "cpu": (cpu or platform.processor() or "desconocido").strip(),
        "nucleos_logicos": str(__import__("os").cpu_count()),
        "sistema": describe_os(),
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def _ops_presentes(results: dict[int, dict[str, OpStats]]) -> list[str]:
    presentes = {op for ops in results.values() for op in ops}
    return [op for op in OPERATIONS if op in presentes]


def format_markdown_table(results: dict[int, dict[str, OpStats]]) -> str:
    """Tabla resumen (media ± desviacion) por operacion y tamano, en Markdown."""
    bits_list = sorted(results.keys())
    lines: list[str] = ["### Tabla de Tiempos y Rendimiento RSA", ""]

    header = "| Operacion | " + " | ".join(f"{b} bits (Media ± Std)" for b in bits_list)
    sep = "| :--- | " + " | ".join(":---:" for _ in bits_list)
    if len(bits_list) >= 2:
        header += f" | Factor ({bits_list[-1]}b / {bits_list[0]}b) |"
        sep += " | :---: |"
    else:
        header += " |"
        sep += " |"
    lines += [header, sep]

    for op in _ops_presentes(results):
        cells = []
        for b in bits_list:
            st = results[b].get(op)
            cells.append(f"{st.format_mean_time()} ± {st.format_std_time()}" if st else "—")
        row = f"| **{op}** | " + " | ".join(cells)
        if len(bits_list) >= 2:
            a, z = results[bits_list[0]].get(op), results[bits_list[-1]].get(op)
            row += f" | **{z.mean_seconds / a.mean_seconds:.2f}x** |" if (a and z and a.mean_seconds > 0) else " | — |"
        else:
            row += " |"
        lines.append(row)
    return "\n".join(lines)


def format_detail_tables(results: dict[int, dict[str, OpStats]]) -> str:
    """Una tabla por tamano con n, media, desviacion, mediana, min, max y ops/s."""
    lines: list[str] = []
    for b in sorted(results):
        lines += [f"#### {b} bits", "",
                  "| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |",
                  "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for op in _ops_presentes({b: results[b]}):
            st = results[b][op]
            lines.append(
                f"| {op} | {st.iterations} | {st.format_mean_time()} | {st.format_std_time()} | "
                f"{st.format_median_time()} | {st.format_min_time()} | {st.format_max_time()} | "
                f"{st.ops_per_second:.2f} |"
            )
        lines.append("")
    return "\n".join(lines)


def format_crt_table(results: dict[int, dict[str, OpStats]]) -> str:
    """Speedup CRT = media sin CRT / media con CRT (solo si se midieron ambas)."""
    filas = []
    for b in sorted(results):
        r = results[b]
        for op in ("Descifrado OAEP", "Firma PSS"):
            con, sin = r.get(op), r.get(op + " sin CRT")
            if con and sin and con.mean_seconds > 0:
                filas.append(f"| {b} | {op} | {sin.format_mean_time()} | {con.format_mean_time()} | "
                             f"**{sin.mean_seconds / con.mean_seconds:.2f}x** |")
    if not filas:
        return ""
    return "\n".join(["### Aceleracion por CRT (Teorema Chino del Resto)", "",
                      "| Bits | Operacion | Sin CRT (media) | Con CRT (media) | Speedup |",
                      "| ---: | :--- | ---: | ---: | ---: |", *filas])


def format_sha_table(filas: list[dict]) -> str:
    con_ref = any("ref_stats" in f for f in filas)
    lines = ["### SHA-256 propio" + (" frente a hashlib (referencia)" if con_ref else ""), ""]
    if con_ref:
        lines += ["| Entrada | n | Propio (media ± std) | MiB/s propio | hashlib (media) | MiB/s hashlib | Veces mas lento | Mismo resumen |",
                  "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |"]
    else:
        lines += ["| Entrada | n | Propio (media ± std) | MiB/s propio |",
                  "| :--- | ---: | ---: | ---: |"]
    for f in filas:
        st = f["stats"]
        mibs = f["bytes"] / st.mean_seconds / (1024 * 1024)
        fila = f"| {f['tamano']} | {st.iterations} | {st.format_mean_time()} ± {st.format_std_time()} | {mibs:.3f}"
        if "ref_stats" in f:
            ref = f["ref_stats"]
            fila += (f" | {ref.format_mean_time()} | {f['bytes'] / ref.mean_seconds / (1024 * 1024):.1f}"
                     f" | {st.mean_seconds / ref.mean_seconds:,.0f}x | {'si' if f['coincide'] else 'NO'}")
        lines.append(fila + " |")
    return "\n".join(lines)


def format_full_report(results, sha_filas, env) -> str:
    """Documento BENCHMARK_RESULTADOS.md completo."""
    partes = [
        "# Resultados del Benchmark RSA-Sign",
        "",
        "Generado automaticamente por `python benchmark.py`. No editar a mano: volver a ejecutar.",
        "",
        "## Entorno",
        "",
        f"- CPU: {env['cpu']} ({env['nucleos_logicos']} nucleos logicos; el benchmark usa 1)",
        f"- Sistema: {env['sistema']}",
        f"- Python: {env['python']}",
        f"- Fecha: {env['fecha']}",
        "",
        "Metodo: `time.perf_counter`, desviacion estandar muestral (n-1). Los tiempos de",
        "generacion de claves varian mucho porque la busqueda de primos es aleatoria.",
        "",
        format_markdown_table(results),
        "",
    ]
    crt = format_crt_table(results)
    if crt:
        partes += [crt, ""]
    partes += ["### Detalle por tamano de clave", "", format_detail_tables(results)]
    if sha_filas:
        partes += [format_sha_table(sha_filas), ""]
    return "\n".join(partes)


def format_text_table(results: dict[int, dict[str, OpStats]]) -> str:
    """Tabla para la terminal."""
    bits_list = sorted(results.keys())
    col_w, op_w = 26, 24
    line_sep = "+" + "-" * (op_w + 2) + ("+" + "-" * (col_w + 2)) * len(bits_list) + "+"
    lines = [line_sep,
             "| " + "Operacion".ljust(op_w) + " | "
             + " | ".join(f"{b} bits (media / ops/s)".center(col_w) for b in bits_list) + " |",
             line_sep]
    for op in _ops_presentes(results):
        cells = []
        for b in bits_list:
            st = results[b].get(op)
            txt = f"{st.format_mean_time()} ({st.ops_per_second:.1f} op/s)" if st else "-"
            cells.append(txt.center(col_w))
        lines.append("| " + op.ljust(op_w) + " | " + " | ".join(cells) + " |")
    lines.append(line_sep)
    return "\n".join(lines)


def export_results_json(results: dict[int, dict[str, OpStats]], filepath: str | Path) -> None:
    """Exporta los resultados estructurados a un archivo JSON."""
    raw = {str(b): {op: asdict(st) for op, st in ops.items()} for b, ops in results.items()}
    Path(filepath).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")


def export_results_csv(results, sha_filas, env, filepath: str | Path) -> None:
    """CSV con una fila por (tamano, operacion) y por medicion de SHA-256."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tipo", "bits", "operacion", "iteraciones", "media_s", "desv_s",
                    "mediana_s", "min_s", "max_s", "ops_por_s", "cpu", "python"])
        for b in sorted(results):
            for op in _ops_presentes({b: results[b]}):
                st = results[b][op]
                w.writerow(["rsa", b, op, st.iterations, f"{st.mean_seconds:.9f}", f"{st.std_seconds:.9f}",
                            f"{st.median_seconds:.9f}", f"{st.min_seconds:.9f}", f"{st.max_seconds:.9f}",
                            f"{st.ops_per_second:.4f}", env["cpu"], env["python"]])
        for fila in sha_filas or []:
            for clave, nombre in (("stats", "SHA-256 propio"), ("ref_stats", "SHA-256 hashlib")):
                if clave in fila:
                    st = fila[clave]
                    w.writerow(["sha256", "", f"{nombre} {fila['tamano']}", st.iterations,
                                f"{st.mean_seconds:.9f}", f"{st.std_seconds:.9f}", f"{st.median_seconds:.9f}",
                                f"{st.min_seconds:.9f}", f"{st.max_seconds:.9f}", f"{st.ops_per_second:.4f}",
                                env["cpu"], env["python"]])


def main(argv: Sequence[str] | None = None, reference_hash: Callable[[bytes], bytes] | None = None) -> int:
    """
    Punto de entrada de linea de comandos.

    :param reference_hash: funcion bytes -> resumen para comparar con el SHA-256
                           propio (la raiz pasa hashlib.sha256(...).digest).
    """
    parser = argparse.ArgumentParser(prog="benchmark", description="Benchmark RSA-Sign (Grupo D)")
    parser.add_argument("--bits", nargs="+", type=int, default=list(DEFAULT_BITS),
                        help="Tamanos de clave (defecto: 1024 2048 3072 4096)")
    parser.add_argument("--iterations", type=int, default=None,
                        help=f"Repeticiones de cada operacion (defecto {DEFAULT_OP_ITERATIONS})")
    parser.add_argument("--keygen-iterations", type=int, default=None,
                        help="Repeticiones de keygen para todos los tamanos (defecto 10/10/5/5)")
    parser.add_argument("--no-sha", action="store_true", help="No medir SHA-256")
    parser.add_argument("--markdown", action="store_true", help="Imprime el informe Markdown")
    parser.add_argument("--output-md", type=str, default=str(RAIZ / "BENCHMARK_RESULTADOS.md"),
                        help="Ruta del informe Markdown (defecto BENCHMARK_RESULTADOS.md)")
    parser.add_argument("--output-csv", type=str, default=str(RAIZ / "BENCHMARK_RESULTADOS.csv"),
                        help="Ruta del CSV (defecto BENCHMARK_RESULTADOS.csv)")
    parser.add_argument("--output-json", type=str, default=None, help="Guarda tambien JSON")
    parser.add_argument("--no-save", action="store_true", help="No escribe archivos")
    parser.add_argument("--quiet", action="store_true", help="Sin mensajes de progreso")
    args = parser.parse_args(argv)

    print("=" * 70)
    print("  EVALUACION DE RENDIMIENTO RSA-Sign")
    print("=" * 70)
    env = detect_environment()
    print(f"  CPU: {env['cpu']} | {env['python']} | {env['sistema']}")

    def logger(msg: str) -> None:
        if not args.quiet:
            print(f"  -> {msg}", flush=True)

    custom = {b: args.iterations for b in args.bits} if args.iterations else None
    kg = {b: args.keygen_iterations for b in args.bits} if args.keygen_iterations else None
    results = run_full_benchmark(bits_list=args.bits, custom_iterations=custom,
                                 progress_callback=logger, keygen_iterations=kg)
    sha_filas = [] if args.no_sha else run_sha_benchmark(reference_hash, progress_callback=logger)

    print("\n" + format_text_table(results))
    informe = format_full_report(results, sha_filas, env)
    if args.markdown:
        print("\n" + informe)
    if not args.no_save:
        Path(args.output_md).write_text(informe + "\n", encoding="utf-8")
        export_results_csv(results, sha_filas, env, args.output_csv)
        print(f"\n[+] Informe Markdown: {args.output_md}")
        print(f"[+] CSV: {args.output_csv}")
    if args.output_json:
        export_results_json(results, args.output_json)
        print(f"[+] JSON: {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
