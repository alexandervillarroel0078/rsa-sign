#!/usr/bin/env python3
"""
Punto de entrada del benchmark de RSA-Sign.

Mide generacion de claves, OAEP, PSS (con y sin CRT) y SHA-256 propio para
1024, 2048, 3072 y 4096 bits, y escribe BENCHMARK_RESULTADOS.md y .csv.

hashlib se importa AQUI (fuera de src/) solo como referencia de velocidad del
SHA-256 propio; la logica criptografica de src/ no lo usa.

Uso:
    python benchmark.py
    python benchmark.py --bits 1024 2048 --iterations 10
    python benchmark.py --no-save --markdown
"""

import hashlib
import sys

from src.benchmark import main


def _sha256_referencia(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


if __name__ == "__main__":
    sys.exit(main(reference_hash=_sha256_referencia))
