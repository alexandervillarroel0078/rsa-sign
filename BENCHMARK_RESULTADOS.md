# Resultados del Benchmark RSA-Sign

Generado automaticamente por `python benchmark.py`. No editar a mano: volver a ejecutar.

## Entorno

- CPU: AMD Ryzen 5 7535HS with Radeon Graphics (12 nucleos logicos; el benchmark usa 1)
- Sistema: Windows-10-10.0.26100-SP0
- Python: CPython 3.10.11
- Fecha: 2026-11-24 09:15

Metodo: `time.perf_counter`, desviacion estandar muestral (n-1). Los tiempos de
generacion de claves varian mucho porque la busqueda de primos es aleatoria.

### Tabla de Tiempos y Rendimiento RSA

| Operacion | 1024 bits (Media ± Std) | 2048 bits (Media ± Std) | 3072 bits (Media ± Std) | 4096 bits (Media ± Std) | Factor (4096b / 1024b) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Generacion Claves** | 124.487 ms ± 33.124 ms | 785.625 ms ± 303.912 ms | 3.309 s ± 1.413 s | 9.566 s ± 2.311 s | **76.84x** |
| **Cifrado OAEP** | 1.236 ms ± 259.04 us | 2.139 ms ± 66.02 us | 3.600 ms ± 495.79 us | 4.362 ms ± 60.04 us | **3.53x** |
| **Descifrado OAEP** | 5.391 ms ± 119.26 us | 31.952 ms ± 1.687 ms | 93.427 ms ± 3.400 ms | 206.684 ms ± 3.395 ms | **38.34x** |
| **Firma PSS** | 5.405 ms ± 244.86 us | 31.465 ms ± 1.459 ms | 98.082 ms ± 16.793 ms | 207.334 ms ± 3.208 ms | **38.36x** |
| **Verificacion PSS** | 1.047 ms ± 44.14 us | 1.831 ms ± 89.63 us | 2.607 ms ± 50.04 us | 3.550 ms ± 373.79 us | **3.39x** |

### Detalle por tamano de clave

#### 1024 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 124.487 ms | 33.124 ms | 124.409 ms | 74.192 ms | 177.464 ms | 8.03 |
| Cifrado OAEP | 10 | 1.236 ms | 259.04 us | 1.132 ms | 1.031 ms | 1.778 ms | 809.24 |
| Descifrado OAEP | 10 | 5.391 ms | 119.26 us | 5.425 ms | 5.219 ms | 5.569 ms | 185.51 |
| Firma PSS | 10 | 5.405 ms | 244.86 us | 5.285 ms | 5.174 ms | 5.927 ms | 185.00 |
| Verificacion PSS | 10 | 1.047 ms | 44.14 us | 1.031 ms | 1.019 ms | 1.165 ms | 954.66 |

#### 2048 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 785.625 ms | 303.912 ms | 746.040 ms | 434.725 ms | 1.252 s | 1.27 |
| Cifrado OAEP | 10 | 2.139 ms | 66.02 us | 2.100 ms | 2.079 ms | 2.254 ms | 467.46 |
| Descifrado OAEP | 10 | 31.952 ms | 1.687 ms | 31.363 ms | 30.293 ms | 35.220 ms | 31.30 |
| Firma PSS | 10 | 31.465 ms | 1.459 ms | 31.058 ms | 29.978 ms | 34.214 ms | 31.78 |
| Verificacion PSS | 10 | 1.831 ms | 89.63 us | 1.797 ms | 1.767 ms | 2.039 ms | 546.09 |

#### 3072 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 3.309 s | 1.413 s | 2.947 s | 1.907 s | 5.195 s | 0.30 |
| Cifrado OAEP | 10 | 3.600 ms | 495.79 us | 3.355 ms | 3.256 ms | 4.638 ms | 277.80 |
| Descifrado OAEP | 10 | 93.427 ms | 3.400 ms | 93.249 ms | 88.987 ms | 100.852 ms | 10.70 |
| Firma PSS | 10 | 98.082 ms | 16.793 ms | 93.631 ms | 89.967 ms | 145.480 ms | 10.20 |
| Verificacion PSS | 10 | 2.607 ms | 50.04 us | 2.596 ms | 2.545 ms | 2.677 ms | 383.55 |

#### 4096 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 9.566 s | 2.311 s | 10.447 s | 5.647 s | 11.565 s | 0.10 |
| Cifrado OAEP | 10 | 4.362 ms | 60.04 us | 4.342 ms | 4.300 ms | 4.471 ms | 229.27 |
| Descifrado OAEP | 10 | 206.684 ms | 3.395 ms | 205.855 ms | 202.794 ms | 212.117 ms | 4.84 |
| Firma PSS | 10 | 207.334 ms | 3.208 ms | 207.793 ms | 201.237 ms | 212.561 ms | 4.82 |
| Verificacion PSS | 10 | 3.550 ms | 373.79 us | 3.429 ms | 3.398 ms | 4.611 ms | 281.68 |

### SHA-256 propio frente a hashlib (referencia)

| Entrada | n | Propio (media ± std) | MiB/s propio | hashlib (media) | MiB/s hashlib | Veces mas lento | Mismo resumen |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| 64 B | 10 | 304.90 us ± 5.30 us | 0.200 | 1.09 us | 55.9 | 279x | si |
| 1 KiB | 10 | 2.680 ms ± 270.92 us | 0.364 | 1.26 us | 776.3 | 2,130x | si |
| 1 MiB | 3 | 2.556 s ± 51.272 ms | 0.391 | 543.48 us | 1840.0 | 4,704x | si |

