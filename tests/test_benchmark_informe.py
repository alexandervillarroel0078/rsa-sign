"""Pruebas del benchmark ampliado (Etapa 5): mediana, CRT, SHA-256, CSV y entorno."""

import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from src.benchmark import (
    OpStats,
    calculate_stats,
    detect_environment,
    export_results_csv,
    format_crt_table,
    format_full_report,
    format_sha_table,
    run_benchmark_for_bits,
    run_sha_benchmark,
)


def _stats(op, bits, mean):
    return OpStats(op, bits, 10, mean, mean / 10, mean * 0.9, mean * 1.1, 1 / mean, mean)


class TestBenchmarkInforme(unittest.TestCase):

    def test_mediana(self):
        st = calculate_stats([0.1, 0.2, 0.9], "Op", 1024)
        self.assertAlmostEqual(st.median_seconds, 0.2)
        self.assertAlmostEqual(calculate_stats([0.1, 0.3], "Op", 1024).median_seconds, 0.2)

    def test_tabla_crt(self):
        res = {2048: {"Descifrado OAEP": _stats("Descifrado OAEP", 2048, 0.01),
                      "Descifrado OAEP sin CRT": _stats("Descifrado OAEP sin CRT", 2048, 0.03)}}
        tabla = format_crt_table(res)
        self.assertIn("3.00x", tabla)
        self.assertEqual(format_crt_table({2048: {"Firma PSS": _stats("Firma PSS", 2048, 0.01)}}), "")

    def test_sha_con_referencia(self):
        filas = run_sha_benchmark(lambda d: hashlib.sha256(d).digest(), sizes=(("64 B", 64),))
        self.assertTrue(filas[0]["coincide"])
        self.assertEqual(filas[0]["stats"].iterations, 10)
        self.assertIn("hashlib", format_sha_table(filas))
        sin_ref = run_sha_benchmark(None, sizes=(("64 B", 64),))
        self.assertNotIn("ref_stats", sin_ref[0])

    def test_keygen_iterations_y_compare_crt(self):
        res = run_benchmark_for_bits(1024, iterations=2, keygen_iterations=1, compare_crt=True)
        self.assertEqual(res["Generacion Claves"].iterations, 1)
        self.assertEqual(res["Cifrado OAEP"].iterations, 2)

    def test_csv_y_informe(self):
        env = detect_environment()
        for clave in ("cpu", "python", "sistema", "fecha"):
            self.assertTrue(env[clave])
        res = {1024: {"Firma PSS": _stats("Firma PSS", 1024, 0.005)}}
        filas = run_sha_benchmark(None, sizes=(("64 B", 64),))
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "b.csv"
            export_results_csv(res, filas, env, ruta)
            with open(ruta, newline="", encoding="utf-8") as f:
                datos = list(csv.DictReader(f))
        self.assertEqual(len(datos), 2)
        self.assertEqual(datos[0]["operacion"], "Firma PSS")
        informe = format_full_report(res, filas, env)
        self.assertIn(env["cpu"], informe)
        self.assertIn("Mediana", informe)


if __name__ == "__main__":
    unittest.main()
