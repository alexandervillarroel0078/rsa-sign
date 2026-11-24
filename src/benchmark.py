"""
Modulo de evaluacion de rendimiento (Benchmark) para RSA.

Mide tiempos de ejecucion para tamanos de clave estandar: 1024, 2048 y 3072 bits
en las 5 operaciones fundamentales del sistema criptografico:
1. Generacion de claves (generate_keypair: p, q, n, e, d con Miller-Rabin)
2. Cifrado asimetrico con relleno OAEP-SHA256 (encrypt_oaep)
3. Descifrado asimetrico con decodificacion OAEP (decrypt_oaep)
4. Firma digital con esquema probabilistico PSS-SHA256 (sign)
5. Verificacion de firma con comparacion en tiempo constante (verify)

Calcula metricas estadisticas (promedio, desviacion estandar, minimo, maximo
y operaciones por segundo) y genera tablas formateadas para consola y Markdown
compatibles con el informe tecnico y la defensa del proyecto.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

try:
    from .rsa import (
        decrypt_oaep,
        encrypt_oaep,
        generate_keypair,
        sign,
        verify,
    )
except ImportError:
    # Soporte para ejecucion directa
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.rsa import (
        decrypt_oaep,
        encrypt_oaep,
        generate_keypair,
        sign,
        verify,
    )


# Tamanos estandar de clave requeridos por la Tarea 15
DEFAULT_BITS: tuple[int, ...] = (1024, 2048, 3072)

# Iteraciones recomendadas por tamano para balancear precision y tiempo total
DEFAULT_ITERATIONS: dict[int, int] = {
    512: 5,
    1024: 5,
    2048: 3,
    3072: 2,
}


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

    def format_mean_time(self) -> str:
        """Formatea el tiempo promedio en unidades legibles (s, ms, us)."""
        sec = self.mean_seconds
        if sec >= 1.0:
            return f"{sec:.3f} s"
        elif sec >= 0.001:
            return f"{sec * 1000.0:.3f} ms"
        else:
            return f"{sec * 1_000_000.0:.2f} us"

    def format_std_time(self) -> str:
        """Formatea la desviacion estandar en unidades legibles."""
        sec = self.std_seconds
        if sec >= 1.0:
            return f"{sec:.3f} s"
        elif sec >= 0.001:
            return f"{sec * 1000.0:.3f} ms"
        else:
            return f"{sec * 1_000_000.0:.2f} us"


def calculate_stats(times: Sequence[float], operation: str, bits: int) -> OpStats:
    """
    Calcula estadisticas a partir de una serie de muestras de tiempo en segundos.
    """
    n = len(times)
    if n == 0:
        raise ValueError("La lista de tiempos no puede estar vacia.")

    mean = sum(times) / n
    variance = sum((x - mean) ** 2 for x in times) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(variance)
    min_t = min(times)
    max_t = max(times)
    ops_sec = (1.0 / mean) if mean > 0 else float("inf")

    return OpStats(
        operation=operation,
        bits=bits,
        iterations=n,
        mean_seconds=mean,
        std_seconds=std,
        min_seconds=min_t,
        max_seconds=max_t,
        ops_per_second=ops_sec,
    )


def time_operation(func: Callable, *args, **kwargs) -> tuple[float, any]:
    """
    Mide el tiempo de ejecucion en segundos de una funcion individual.
    Utiliza time.perf_counter para maxima precision monotona.
    """
    t0 = time.perf_counter()
    result = func(*args, **kwargs)
    t1 = time.perf_counter()
    return (t1 - t0, result)


def run_benchmark_for_bits(
    bits: int,
    iterations: int = 3,
    sample_message: bytes = b"Benchmark RSA-OAEP-PSS ELC107 Grupo D",
    progress_callback: Callable[[str], None] | None = None,
) -> dict[str, OpStats]:
    """
    Ejecuta el benchmark completo para un tamano especifico de clave RSA.

    Mide:
    1. Generacion de par de claves (p, q, n, e, d)
    2. Cifrado con relleno OAEP
    3. Descifrado con relleno OAEP
    4. Firma digital con esquema probabilistico PSS
    5. Verificacion de firma digital PSS (con comparacion en tiempo constante)

    :param bits: Longitud del modulo n en bits (1024, 2048, 3072).
    :param iterations: Cantidad de repeticiones para promediar.
    :param sample_message: Mensaje en bytes a procesar.
    :param progress_callback: Funcion opcional para reportar avance.
    :return: Diccionario con {operacion: OpStats}.
    """
    if bits < 528:
        raise ValueError(
            f"Tamano de clave {bits} bits insuficiente para OAEP-SHA256 "
            f"(requiere al menos 528 bits / 66 bytes)."
        )

    if progress_callback:
        progress_callback(f"Iniciando pruebas para {bits} bits ({iterations} iteraciones)...")

    # 1. Medir generacion de claves
    keygen_times: list[float] = []
    keys_pool: list[tuple[tuple[int, int], tuple[int, int]]] = []

    for i in range(iterations):
        if progress_callback:
            progress_callback(f"[{bits}b] Generando par de claves ({i + 1}/{iterations})...")
        t, keypair = time_operation(generate_keypair, bits)
        keygen_times.append(t)
        keys_pool.append(keypair)

    # Usar el primer par de claves para las operaciones criptograficas
    pub, priv = keys_pool[0]

    # 2. Medir cifrado OAEP
    encrypt_times: list[float] = []
    ciphertexts: list[bytes] = []
    for i in range(iterations):
        if progress_callback:
            progress_callback(f"[{bits}b] Cifrado OAEP ({i + 1}/{iterations})...")
        t, ct = time_operation(encrypt_oaep, sample_message, pub)
        encrypt_times.append(t)
        ciphertexts.append(ct)

    # 3. Medir descifrado OAEP
    decrypt_times: list[float] = []
    for i in range(iterations):
        ct = ciphertexts[i % len(ciphertexts)]
        if progress_callback:
            progress_callback(f"[{bits}b] Descifrado OAEP ({i + 1}/{iterations})...")
        t, pt = time_operation(decrypt_oaep, ct, priv)
        if pt != sample_message:
            raise RuntimeError(f"Falla de integridad: texto descifrado no coincide ({bits}b)")
        decrypt_times.append(t)

    # 4. Medir firma digital PSS
    sign_times: list[float] = []
    signatures: list[bytes] = []
    for i in range(iterations):
        if progress_callback:
            progress_callback(f"[{bits}b] Firma PSS ({i + 1}/{iterations})...")
        t, sig = time_operation(sign, sample_message, priv)
        sign_times.append(t)
        signatures.append(sig)

    # 5. Medir verificacion de firma PSS (con comparacion en tiempo constante)
    verify_times: list[float] = []
    for i in range(iterations):
        sig = signatures[i % len(signatures)]
        if progress_callback:
            progress_callback(f"[{bits}b] Verificacion PSS ({i + 1}/{iterations})...")
        t, ok = time_operation(verify, sample_message, sig, pub)
        if not ok:
            raise RuntimeError(f"Falla de integridad: firma no valida en verificacion ({bits}b)")
        verify_times.append(t)

    return {
        "Generacion Claves": calculate_stats(keygen_times, "Generacion Claves", bits),
        "Cifrado OAEP": calculate_stats(encrypt_times, "Cifrado OAEP", bits),
        "Descifrado OAEP": calculate_stats(decrypt_times, "Descifrado OAEP", bits),
        "Firma PSS": calculate_stats(sign_times, "Firma PSS", bits),
        "Verificacion PSS": calculate_stats(verify_times, "Verificacion PSS", bits),
    }


def run_full_benchmark(
    bits_list: Sequence[int] = DEFAULT_BITS,
    custom_iterations: dict[int, int] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> dict[int, dict[str, OpStats]]:
    """
    Ejecuta el conjunto completo de benchmarks sobre todos los tamanos de clave especificados.

    :param bits_list: Lista de tamanos de clave a evaluar (por defecto: 1024, 2048, 3072).
    :param custom_iterations: Mapeo opcional {bits: num_iteraciones}.
    :param progress_callback: Funcion opcional para retroalimentacion de progreso.
    :return: Diccionario estructurado {bits: {operacion: OpStats}}.
    """
    results: dict[int, dict[str, OpStats]] = {}

    for bits in bits_list:
        iters = 3
        if custom_iterations and bits in custom_iterations:
            iters = custom_iterations[bits]
        elif bits in DEFAULT_ITERATIONS:
            iters = DEFAULT_ITERATIONS[bits]

        stats_for_bits = run_benchmark_for_bits(
            bits=bits,
            iterations=iters,
            progress_callback=progress_callback,
        )
        results[bits] = stats_for_bits

    return results


def format_markdown_table(results: dict[int, dict[str, OpStats]]) -> str:
    """
    Genera una tabla en formato Markdown con los resultados del benchmark,
    ideal para copiar directamente en el informe tecnico (APA) o en README.md.
    """
    bits_list = sorted(results.keys())
    operations = [
        "Generacion Claves",
        "Cifrado OAEP",
        "Descifrado OAEP",
        "Firma PSS",
        "Verificacion PSS",
    ]

    lines: list[str] = []
    lines.append("### Tabla de Tiempos y Rendimiento RSA (Tarea 15)")
    lines.append("")

    # Encabezado
    header = "| Operacion | " + " | ".join(f"{b} bits (Media ± Std)" for b in bits_list)
    if len(bits_list) >= 2:
        header += f" | Factor Escalamiento ({bits_list[-1]}b / {bits_list[0]}b) |"
    else:
        header += " |"
    lines.append(header)

    # Separador
    sep = "| :--- | " + " | ".join(":---:" for _ in bits_list)
    if len(bits_list) >= 2:
        sep += " | :---: |"
    else:
        sep += " |"
    lines.append(sep)

    # Filas de operaciones
    for op in operations:
        row = f"| **{op}** | "
        times_per_bit: list[float] = []
        cells = []
        for b in bits_list:
            st = results[b][op]
            times_per_bit.append(st.mean_seconds)
            cells.append(f"{st.format_mean_time()} ± {st.format_std_time()}")
        row += " | ".join(cells)

        if len(bits_list) >= 2:
            base_t = times_per_bit[0]
            max_t = times_per_bit[-1]
            factor = (max_t / base_t) if base_t > 0 else 1.0
            row += f" | **{factor:.2f}x** |"
        else:
            row += " |"
        lines.append(row)

    lines.append("")
    lines.append("> **Analisis de Resultados:**")
    lines.append("> - **Asimetria Publica vs Privada:** Las operaciones publicas (*Cifrado OAEP* y *Verificacion PSS*) utilizan el exponente fijo $e=65537$ (17 bits), por lo que ejecutan en pocos milisegundos incluso a 3072 bits.")
    lines.append("> - **Costo de Clave Privada:** Las operaciones privadas (*Descifrado OAEP* y *Firma PSS*) emplean el exponente completo $d$, cuya longitud en bits coincide con el modulo $n$. El tiempo crece aproximadamente de forma cubica $O(b^3)$ respecto al tamano de bits.")
    lines.append("> - **Generacion de Claves:** Requiere la busqueda probabilistica de dos primos independientes mediante 40 rondas de Miller-Rabin, siendo la operacion mas exigente a 3072 bits.")

    return "\n".join(lines)


def format_text_table(results: dict[int, dict[str, OpStats]]) -> str:
    """
    Genera una tabla visual formateada con caracteres ASCII/Unicode para terminal.
    """
    bits_list = sorted(results.keys())
    operations = [
        "Generacion Claves",
        "Cifrado OAEP",
        "Descifrado OAEP",
        "Firma PSS",
        "Verificacion PSS",
    ]

    col_w = 26
    op_w = 22

    line_sep = "+" + "-" * (op_w + 2) + ("+" + "-" * (col_w + 2)) * len(bits_list) + "+"

    lines: list[str] = [
        line_sep,
        "| " + "Operacion".ljust(op_w) + " | " + " | ".join(f"{b} bits (media / ops/s)".center(col_w) for b in bits_list) + " |",
        line_sep,
    ]

    for op in operations:
        cells = []
        for b in bits_list:
            st = results[b][op]
            cell_str = f"{st.format_mean_time()} ({st.ops_per_second:.1f} op/s)"
            cells.append(cell_str.center(col_w))
        row = "| " + op.ljust(op_w) + " | " + " | ".join(cells) + " |"
        lines.append(row)

    lines.append(line_sep)
    return "\n".join(lines)


def export_results_json(results: dict[int, dict[str, OpStats]], filepath: str | Path) -> None:
    """Exporta los resultados estructurados a un archivo JSON."""
    raw: dict[str, dict[str, any]] = {}
    for b, ops in results.items():
        raw[str(b)] = {op_name: asdict(st) for op_name, st in ops.items()}
    path = Path(filepath)
    path.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada de linea de comandos para ejecutar el benchmark."""
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="Benchmark criptografico RSA (1024, 2048 y 3072 bits) - Tarea 15 (Grupo D)",
    )
    parser.add_argument(
        "--bits",
        nargs="+",
        type=int,
        default=[1024, 2048, 3072],
        help="Tamanos de clave en bits a evaluar (defecto: 1024 2048 3072)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="Numero fijo de iteraciones para todos los tamanos (por defecto automatico)",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Imprime la salida directamente en formato Markdown para el informe",
    )
    parser.add_argument(
        "--output-md",
        type=str,
        default=None,
        help="Guarda el informe en formato Markdown en la ruta especificada",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Guarda los datos en formato JSON en la ruta especificada",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suprime los mensajes de progreso durante la ejecucion",
    )

    args = parser.parse_args(argv)

    print("=" * 70)
    print("  EVALUACION DE RENDIMIENTO RSA (Tarea 15: Benchmark 1024, 2048, 3072)")
    print("  ELC107 Criptografia y Seguridad - Grupo D")
    print("=" * 70)

    custom_iters = None
    if args.iterations:
        custom_iters = {b: args.iterations for b in args.bits}

    def logger(msg: str) -> None:
        if not args.quiet:
            print(f"  -> {msg}")

    results = run_full_benchmark(
        bits_list=args.bits,
        custom_iterations=custom_iters,
        progress_callback=logger,
    )

    print("\n" + "=" * 70)
    print("  RESULTADOS CONSOLA")
    print("=" * 70)
    print(format_text_table(results))

    md_table = format_markdown_table(results)

    if args.markdown:
        print("\n" + md_table)

    if args.output_md:
        out_path = Path(args.output_md)
        out_path.write_text(md_table, encoding="utf-8")
        print(f"\n[+] Tabla Markdown guardada exitosamente en: {out_path}")

    if args.output_json:
        export_results_json(results, args.output_json)
        print(f"[+] Datos brutos JSON guardados exitosamente en: {args.output_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
