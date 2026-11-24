# Resultados del Benchmark RSA-Sign

Generado automaticamente por `python benchmark.py`. No editar a mano: volver a ejecutar.

## Entorno

- CPU: AMD Ryzen 5 7535HS with Radeon Graphics (12 nucleos logicos; el benchmark usa 1)
- Sistema: Windows 11 (build 26100)
- Python: CPython 3.10.11
- Fecha: 2026-11-24 09:29

Metodo: `time.perf_counter`, desviacion estandar muestral (n-1). Los tiempos de
generacion de claves varian mucho porque la busqueda de primos es aleatoria.

### Tabla de Tiempos y Rendimiento RSA

| Operacion | 1024 bits (Media ± Std) | 2048 bits (Media ± Std) | 3072 bits (Media ± Std) | 4096 bits (Media ± Std) | Factor (4096b / 1024b) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Generacion Claves** | 119.241 ms ± 37.993 ms | 911.767 ms ± 310.416 ms | 5.480 s ± 3.058 s | 8.022 s ± 2.584 s | **67.27x** |
| **Cifrado OAEP** | 1.094 ms ± 94.53 us | 2.565 ms ± 701.03 us | 4.920 ms ± 1.409 ms | 6.066 ms ± 726.42 us | **5.55x** |
| **Descifrado OAEP** | 3.465 ms ± 502.37 us | 12.864 ms ± 1.154 ms | 38.441 ms ± 4.814 ms | 75.031 ms ± 2.851 ms | **21.65x** |
| **Descifrado OAEP sin CRT** | 7.408 ms ± 924.94 us | 31.780 ms ± 2.030 ms | 108.465 ms ± 2.869 ms | 231.030 ms ± 3.614 ms | **31.19x** |
| **Firma PSS** | 3.736 ms ± 618.93 us | 10.782 ms ± 174.87 us | 39.093 ms ± 8.336 ms | 71.688 ms ± 3.002 ms | **19.19x** |
| **Firma PSS sin CRT** | 7.114 ms ± 761.77 us | 29.284 ms ± 988.75 us | 106.767 ms ± 5.231 ms | 232.464 ms ± 5.724 ms | **32.68x** |
| **Verificacion PSS** | 1.410 ms ± 363.18 us | 1.728 ms ± 95.52 us | 3.399 ms ± 1.458 ms | 5.090 ms ± 1.215 ms | **3.61x** |

### Aceleracion por CRT (Teorema Chino del Resto)

| Bits | Operacion | Sin CRT (media) | Con CRT (media) | Speedup |
| ---: | :--- | ---: | ---: | ---: |
| 1024 | Descifrado OAEP | 7.408 ms | 3.465 ms | **2.14x** |
| 1024 | Firma PSS | 7.114 ms | 3.736 ms | **1.90x** |
| 2048 | Descifrado OAEP | 31.780 ms | 12.864 ms | **2.47x** |
| 2048 | Firma PSS | 29.284 ms | 10.782 ms | **2.72x** |
| 3072 | Descifrado OAEP | 108.465 ms | 38.441 ms | **2.82x** |
| 3072 | Firma PSS | 106.767 ms | 39.093 ms | **2.73x** |
| 4096 | Descifrado OAEP | 231.030 ms | 75.031 ms | **3.08x** |
| 4096 | Firma PSS | 232.464 ms | 71.688 ms | **3.24x** |

### Detalle por tamano de clave

#### 1024 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 119.241 ms | 37.993 ms | 112.721 ms | 78.195 ms | 201.344 ms | 8.39 |
| Cifrado OAEP | 10 | 1.094 ms | 94.53 us | 1.044 ms | 1.019 ms | 1.288 ms | 914.41 |
| Descifrado OAEP | 10 | 3.465 ms | 502.37 us | 3.355 ms | 2.925 ms | 4.147 ms | 288.60 |
| Descifrado OAEP sin CRT | 10 | 7.408 ms | 924.94 us | 7.190 ms | 6.223 ms | 8.673 ms | 135.00 |
| Firma PSS | 10 | 3.736 ms | 618.93 us | 3.625 ms | 2.885 ms | 4.799 ms | 267.64 |
| Firma PSS sin CRT | 10 | 7.114 ms | 761.77 us | 7.353 ms | 5.466 ms | 8.063 ms | 140.57 |
| Verificacion PSS | 10 | 1.410 ms | 363.18 us | 1.400 ms | 968.20 us | 1.869 ms | 708.99 |

#### 2048 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 911.767 ms | 310.416 ms | 826.818 ms | 526.872 ms | 1.470 s | 1.10 |
| Cifrado OAEP | 10 | 2.565 ms | 701.03 us | 2.201 ms | 1.901 ms | 3.715 ms | 389.91 |
| Descifrado OAEP | 10 | 12.864 ms | 1.154 ms | 12.799 ms | 11.046 ms | 14.916 ms | 77.74 |
| Descifrado OAEP sin CRT | 10 | 31.780 ms | 2.030 ms | 32.118 ms | 28.897 ms | 34.947 ms | 31.47 |
| Firma PSS | 10 | 10.782 ms | 174.87 us | 10.795 ms | 10.562 ms | 11.123 ms | 92.74 |
| Firma PSS sin CRT | 10 | 29.284 ms | 988.75 us | 28.879 ms | 28.517 ms | 31.752 ms | 34.15 |
| Verificacion PSS | 10 | 1.728 ms | 95.52 us | 1.693 ms | 1.631 ms | 1.915 ms | 578.85 |

#### 3072 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 5.480 s | 3.058 s | 4.183 s | 2.683 s | 9.054 s | 0.18 |
| Cifrado OAEP | 10 | 4.920 ms | 1.409 ms | 4.362 ms | 3.557 ms | 7.128 ms | 203.25 |
| Descifrado OAEP | 10 | 38.441 ms | 4.814 ms | 37.306 ms | 32.337 ms | 48.544 ms | 26.01 |
| Descifrado OAEP sin CRT | 10 | 108.465 ms | 2.869 ms | 108.560 ms | 103.423 ms | 112.439 ms | 9.22 |
| Firma PSS | 10 | 39.093 ms | 8.336 ms | 35.509 ms | 29.938 ms | 54.180 ms | 25.58 |
| Firma PSS sin CRT | 10 | 106.767 ms | 5.231 ms | 107.657 ms | 99.712 ms | 117.078 ms | 9.37 |
| Verificacion PSS | 10 | 3.399 ms | 1.458 ms | 2.596 ms | 2.359 ms | 6.081 ms | 294.18 |

#### 4096 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 8.022 s | 2.584 s | 8.034 s | 5.348 s | 11.655 s | 0.12 |
| Cifrado OAEP | 10 | 6.066 ms | 726.42 us | 6.371 ms | 4.768 ms | 6.802 ms | 164.84 |
| Descifrado OAEP | 10 | 75.031 ms | 2.851 ms | 76.307 ms | 69.593 ms | 78.208 ms | 13.33 |
| Descifrado OAEP sin CRT | 10 | 231.030 ms | 3.614 ms | 230.979 ms | 224.386 ms | 236.247 ms | 4.33 |
| Firma PSS | 10 | 71.688 ms | 3.002 ms | 71.867 ms | 67.600 ms | 75.868 ms | 13.95 |
| Firma PSS sin CRT | 10 | 232.464 ms | 5.724 ms | 232.214 ms | 223.053 ms | 242.605 ms | 4.30 |
| Verificacion PSS | 10 | 5.090 ms | 1.215 ms | 5.926 ms | 3.273 ms | 6.114 ms | 196.47 |

### SHA-256 propio frente a hashlib (referencia)

| Entrada | n | Propio (media ± std) | MiB/s propio | hashlib (media) | MiB/s hashlib | Veces mas lento | Mismo resumen |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| 64 B | 10 | 499.58 us ± 103.80 us | 0.122 | 1.98 us | 30.8 | 252x | si |
| 1 KiB | 10 | 3.645 ms ± 983.24 us | 0.268 | 1.39 us | 704.1 | 2,628x | si |
| 1 MiB | 3 | 3.539 s ± 25.388 ms | 0.283 | 513.76 us | 1946.4 | 6,889x | si |

