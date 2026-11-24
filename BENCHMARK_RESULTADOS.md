# Resultados del Benchmark RSA-Sign

Generado automaticamente por `python benchmark.py`. No editar a mano: volver a ejecutar.

## Entorno

- CPU: AMD Ryzen 5 7535HS with Radeon Graphics (12 nucleos logicos; el benchmark usa 1)
- Sistema: Windows 11 (build 26100)
- Python: CPython 3.10.11
- Fecha: 2026-11-24 10:22

Metodo: `time.perf_counter`, desviacion estandar muestral (n-1). Los tiempos de
generacion de claves varian mucho porque la busqueda de primos es aleatoria.

### Tabla de Tiempos y Rendimiento RSA

| Operacion | 1024 bits (Media ± Std) | 2048 bits (Media ± Std) | 3072 bits (Media ± Std) | 4096 bits (Media ± Std) | Factor (4096b / 1024b) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Generacion Claves** | 121.295 ms ± 34.368 ms | 863.037 ms ± 381.996 ms | 3.175 s ± 1.095 s | 5.934 s ± 2.039 s | **48.92x** |
| **Cifrado OAEP** | 979.61 us ± 38.34 us | 1.937 ms ± 19.15 us | 2.959 ms ± 73.59 us | 4.039 ms ± 50.67 us | **4.12x** |
| **Descifrado OAEP** | 2.943 ms ± 172.80 us | 11.080 ms ± 396.01 us | 28.695 ms ± 770.01 us | 59.151 ms ± 709.20 us | **20.10x** |
| **Descifrado OAEP sin CRT** | 5.559 ms ± 358.68 us | 28.978 ms ± 376.71 us | 86.455 ms ± 1.021 ms | 192.568 ms ± 986.32 us | **34.64x** |
| **Firma PSS** | 2.904 ms ± 258.74 us | 10.476 ms ± 255.24 us | 27.628 ms ± 306.19 us | 60.081 ms ± 2.617 ms | **20.69x** |
| **Firma PSS sin CRT** | 5.325 ms ± 290.54 us | 29.289 ms ± 601.03 us | 87.021 ms ± 2.466 ms | 191.827 ms ± 1.586 ms | **36.02x** |
| **Verificacion PSS** | 1.036 ms ± 248.36 us | 1.858 ms ± 250.16 us | 2.454 ms ± 126.30 us | 3.377 ms ± 240.55 us | **3.26x** |

### Aceleracion por CRT (Teorema Chino del Resto)

| Bits | Operacion | Sin CRT (media) | Con CRT (media) | Speedup |
| ---: | :--- | ---: | ---: | ---: |
| 1024 | Descifrado OAEP | 5.559 ms | 2.943 ms | **1.89x** |
| 1024 | Firma PSS | 5.325 ms | 2.904 ms | **1.83x** |
| 2048 | Descifrado OAEP | 28.978 ms | 11.080 ms | **2.62x** |
| 2048 | Firma PSS | 29.289 ms | 10.476 ms | **2.80x** |
| 3072 | Descifrado OAEP | 86.455 ms | 28.695 ms | **3.01x** |
| 3072 | Firma PSS | 87.021 ms | 27.628 ms | **3.15x** |
| 4096 | Descifrado OAEP | 192.568 ms | 59.151 ms | **3.26x** |
| 4096 | Firma PSS | 191.827 ms | 60.081 ms | **3.19x** |

### Detalle por tamano de clave

#### 1024 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 121.295 ms | 34.368 ms | 125.860 ms | 71.824 ms | 201.056 ms | 8.24 |
| Cifrado OAEP | 10 | 979.61 us | 38.34 us | 967.10 us | 944.40 us | 1.067 ms | 1020.81 |
| Descifrado OAEP | 10 | 2.943 ms | 172.80 us | 2.880 ms | 2.768 ms | 3.327 ms | 339.78 |
| Descifrado OAEP sin CRT | 10 | 5.559 ms | 358.68 us | 5.555 ms | 5.135 ms | 6.095 ms | 179.88 |
| Firma PSS | 10 | 2.904 ms | 258.74 us | 2.784 ms | 2.716 ms | 3.523 ms | 344.33 |
| Firma PSS sin CRT | 10 | 5.325 ms | 290.54 us | 5.205 ms | 5.096 ms | 5.913 ms | 187.79 |
| Verificacion PSS | 10 | 1.036 ms | 248.36 us | 951.45 us | 931.40 us | 1.739 ms | 965.33 |

#### 2048 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 10 | 863.037 ms | 381.996 ms | 792.342 ms | 461.927 ms | 1.775 s | 1.16 |
| Cifrado OAEP | 10 | 1.937 ms | 19.15 us | 1.933 ms | 1.915 ms | 1.985 ms | 516.28 |
| Descifrado OAEP | 10 | 11.080 ms | 396.01 us | 10.922 ms | 10.634 ms | 11.624 ms | 90.25 |
| Descifrado OAEP sin CRT | 10 | 28.978 ms | 376.71 us | 28.810 ms | 28.760 ms | 29.946 ms | 34.51 |
| Firma PSS | 10 | 10.476 ms | 255.24 us | 10.387 ms | 10.265 ms | 11.088 ms | 95.46 |
| Firma PSS sin CRT | 10 | 29.289 ms | 601.03 us | 29.004 ms | 28.919 ms | 30.823 ms | 34.14 |
| Verificacion PSS | 10 | 1.858 ms | 250.16 us | 1.751 ms | 1.648 ms | 2.333 ms | 538.36 |

#### 3072 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 3.175 s | 1.095 s | 2.685 s | 2.487 s | 5.096 s | 0.31 |
| Cifrado OAEP | 10 | 2.959 ms | 73.59 us | 2.937 ms | 2.894 ms | 3.152 ms | 337.90 |
| Descifrado OAEP | 10 | 28.695 ms | 770.01 us | 28.639 ms | 27.647 ms | 29.776 ms | 34.85 |
| Descifrado OAEP sin CRT | 10 | 86.455 ms | 1.021 ms | 86.698 ms | 84.583 ms | 87.754 ms | 11.57 |
| Firma PSS | 10 | 27.628 ms | 306.19 us | 27.579 ms | 27.237 ms | 28.207 ms | 36.19 |
| Firma PSS sin CRT | 10 | 87.021 ms | 2.466 ms | 86.198 ms | 85.256 ms | 93.589 ms | 11.49 |
| Verificacion PSS | 10 | 2.454 ms | 126.30 us | 2.410 ms | 2.352 ms | 2.785 ms | 407.55 |

#### 4096 bits

| Operacion | n | Media | Desv. est. | Mediana | Min | Max | ops/s |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Generacion Claves | 5 | 5.934 s | 2.039 s | 5.286 s | 3.467 s | 8.706 s | 0.17 |
| Cifrado OAEP | 10 | 4.039 ms | 50.67 us | 4.023 ms | 3.967 ms | 4.144 ms | 247.56 |
| Descifrado OAEP | 10 | 59.151 ms | 709.20 us | 58.882 ms | 58.527 ms | 60.394 ms | 16.91 |
| Descifrado OAEP sin CRT | 10 | 192.568 ms | 986.32 us | 192.458 ms | 190.800 ms | 193.917 ms | 5.19 |
| Firma PSS | 10 | 60.081 ms | 2.617 ms | 59.156 ms | 58.067 ms | 66.615 ms | 16.64 |
| Firma PSS sin CRT | 10 | 191.827 ms | 1.586 ms | 192.055 ms | 189.911 ms | 193.458 ms | 5.21 |
| Verificacion PSS | 10 | 3.377 ms | 240.55 us | 3.303 ms | 3.187 ms | 3.939 ms | 296.13 |

### SHA-256 propio frente a hashlib (referencia)

| Entrada | n | Propio (media ± std) | MiB/s propio | hashlib (media) | MiB/s hashlib | Veces mas lento | Mismo resumen |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| 64 B | 10 | 382.48 us ± 109.05 us | 0.160 | 0.98 us | 62.2 | 389x | si |
| 1 KiB | 10 | 2.553 ms ± 154.87 us | 0.383 | 1.26 us | 774.4 | 2,024x | si |
| 1 MiB | 3 | 2.279 s ± 28.012 ms | 0.439 | 481.10 us | 2078.6 | 4,737x | si |

