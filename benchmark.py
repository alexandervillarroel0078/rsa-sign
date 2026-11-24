#!/usr/bin/env python3
"""
Punto de entrada raiz para el Benchmark de Rendimiento RSA (Tarea 15).

Permite evaluar los tiempos de ejecucion para claves de 1024, 2048 y 3072 bits
en generacion de claves, cifrado/descifrado OAEP y firma/verificacion PSS.

Uso:
    python benchmark.py
    python benchmark.py --bits 1024 2048 --iterations 3
    python benchmark.py --markdown --output-md BENCHMARK_RESULTADOS.md
"""

import sys
from src.benchmark import main

if __name__ == "__main__":
    sys.exit(main())
