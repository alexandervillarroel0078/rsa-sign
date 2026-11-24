"""
Pruebas unitarias para el modulo de benchmark de rendimiento RSA (Tarea 15).

Verifica el calculo estadistico, la medicion precisa de operaciones criptograficas,
la generacion de tablas en formato texto/Markdown y la exportacion de resultados.
"""

import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark import (
    OpStats,
    calculate_stats,
    export_results_json,
    format_markdown_table,
    format_text_table,
    run_benchmark_for_bits,
    time_operation,
)


class TestBenchmarkStats(unittest.TestCase):
    """Pruebas para calculos estadisticos y formateo de unidades."""

    def test_calculate_stats_valores_conocidos(self):
        """Verifica media, min, max, std y ops/s para una serie conocida."""
        muestras = [0.010, 0.020, 0.030]
        stats = calculate_stats(muestras, "TestOp", 1024)

        self.assertEqual(stats.operation, "TestOp")
        self.assertEqual(stats.bits, 1024)
        self.assertEqual(stats.iterations, 3)
        self.assertAlmostEqual(stats.mean_seconds, 0.020, places=5)
        self.assertAlmostEqual(stats.min_seconds, 0.010, places=5)
        self.assertAlmostEqual(stats.max_seconds, 0.030, places=5)
        self.assertAlmostEqual(stats.ops_per_second, 50.0, places=2)
        # std muestral de [0.01, 0.02, 0.03] con ddof=1 es 0.01
        self.assertAlmostEqual(stats.std_seconds, 0.010, places=5)

    def test_calculate_stats_lista_vacia(self):
        """Lista vacia debe lanzar ValueError."""
        with self.assertRaises(ValueError):
            calculate_stats([], "Vacia", 1024)

    def test_format_units(self):
        """Verifica conversion automatica a s, ms y us."""
        s1 = OpStats("Op", 1024, 1, 1.5, 0.2, 1.3, 1.7, 0.67)
        self.assertIn("s", s1.format_mean_time())

        s2 = OpStats("Op", 1024, 1, 0.015, 0.002, 0.013, 0.017, 66.7)
        self.assertIn("ms", s2.format_mean_time())

        s3 = OpStats("Op", 1024, 1, 0.00005, 0.00001, 0.00004, 0.00006, 20000.0)
        self.assertIn("us", s3.format_mean_time())

    def test_time_operation(self):
        """Mide ejecucion de una funcion dummy y comprueba resultado y tiempo."""
        def dummy_add(a, b):
            return a + b

        elapsed, result = time_operation(dummy_add, 15, 25)
        self.assertEqual(result, 40)
        self.assertGreaterEqual(elapsed, 0.0)


class TestBenchmarkExecution(unittest.TestCase):
    """Pruebas de ejecucion real del benchmark (en modo rapido con 512 bits)."""

    def test_run_benchmark_for_bits_1024(self):
        """Ejecuta el flujo completo para 1024 bits (1 iteracion) y valida metricas."""
        res = run_benchmark_for_bits(bits=1024, iterations=1)

        operaciones_esperadas = {
            "Generacion Claves",
            "Cifrado OAEP",
            "Descifrado OAEP",
            "Firma PSS",
            "Verificacion PSS",
        }
        self.assertEqual(set(res.keys()), operaciones_esperadas)

        for op_name, stats in res.items():
            self.assertEqual(stats.bits, 1024)
            self.assertEqual(stats.iterations, 1)
            self.assertGreater(stats.mean_seconds, 0.0)
            self.assertGreater(stats.ops_per_second, 0.0)

    def test_run_benchmark_bits_insuficientes(self):
        """Modulos menores a 528 bits no admiten OAEP-SHA256 y deben lanzar ValueError."""
        with self.assertRaises(ValueError):
            run_benchmark_for_bits(bits=512, iterations=1)

    def test_format_tables(self):
        """Comprueba que los generadores de tabla produzcan encabezados y filas validas."""
        mock_results = {
            1024: {
                "Generacion Claves": OpStats("Generacion Claves", 1024, 1, 0.35, 0.0, 0.35, 0.35, 2.8),
                "Cifrado OAEP": OpStats("Cifrado OAEP", 1024, 1, 0.001, 0.0, 0.001, 0.001, 1000.0),
                "Descifrado OAEP": OpStats("Descifrado OAEP", 1024, 1, 0.007, 0.0, 0.007, 0.007, 142.0),
                "Firma PSS": OpStats("Firma PSS", 1024, 1, 0.006, 0.0, 0.006, 0.006, 166.0),
                "Verificacion PSS": OpStats("Verificacion PSS", 1024, 1, 0.001, 0.0, 0.001, 0.001, 1000.0),
            }
        }

        md_output = format_markdown_table(mock_results)
        self.assertIn("### Tabla de Tiempos y Rendimiento RSA", md_output)
        self.assertIn("1024 bits", md_output)
        self.assertIn("Generacion Claves", md_output)

        txt_output = format_text_table(mock_results)
        self.assertIn("Generacion Claves", txt_output)
        self.assertIn("1024 bits", txt_output)

    def test_export_results_json(self):
        """Valida que la exportacion JSON escriba un archivo valido con los datos."""
        mock_results = {
            1024: {
                "Generacion Claves": OpStats("Generacion Claves", 1024, 1, 0.35, 0.0, 0.35, 0.35, 2.8),
                "Cifrado OAEP": OpStats("Cifrado OAEP", 1024, 1, 0.001, 0.0, 0.001, 0.001, 1000.0),
                "Descifrado OAEP": OpStats("Descifrado OAEP", 1024, 1, 0.007, 0.0, 0.007, 0.007, 142.0),
                "Firma PSS": OpStats("Firma PSS", 1024, 1, 0.006, 0.0, 0.006, 0.006, 166.0),
                "Verificacion PSS": OpStats("Verificacion PSS", 1024, 1, 0.001, 0.0, 0.001, 0.001, 1000.0),
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = Path(tmpdir) / "bench.json"
            export_results_json(mock_results, json_file)

            self.assertTrue(json_file.exists())
            data = json.loads(json_file.read_text(encoding="utf-8"))
            self.assertIn("1024", data)
            self.assertIn("Generacion Claves", data["1024"])
            self.assertEqual(data["1024"]["Generacion Claves"]["bits"], 1024)


if __name__ == "__main__":
    unittest.main()
