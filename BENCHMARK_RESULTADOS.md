### Tabla de Tiempos y Rendimiento RSA (Tarea 15)

| Operacion | 1024 bits (Media ± Std) | 2048 bits (Media ± Std) | 3072 bits (Media ± Std) | Factor Escalamiento (3072b / 1024b) |
| :--- | :---: | :---: | :---: | :---: |
| **Generacion Claves** | 173.382 ms ± 56.038 ms | 2.357 s ± 639.798 ms | 2.659 s ± 993.546 ms | **15.33x** |
| **Cifrado OAEP** | 1.124 ms ± 48.03 us | 2.056 ms ± 57.68 us | 3.679 ms ± 957.01 us | **3.27x** |
| **Descifrado OAEP** | 6.271 ms ± 47.90 us | 33.193 ms ± 52.55 us | 105.160 ms ± 5.996 ms | **16.77x** |
| **Firma PSS** | 6.276 ms ± 114.57 us | 32.716 ms ± 218.43 us | 99.500 ms ± 435.65 us | **15.85x** |
| **Verificacion PSS** | 1.068 ms ± 13.95 us | 1.727 ms ± 28.75 us | 2.615 ms ± 21.88 us | **2.45x** |

> **Analisis de Resultados:**
> - **Asimetria Publica vs Privada:** Las operaciones publicas (*Cifrado OAEP* y *Verificacion PSS*) utilizan el exponente fijo $e=65537$ (17 bits), por lo que ejecutan en pocos milisegundos incluso a 3072 bits.
> - **Costo de Clave Privada:** Las operaciones privadas (*Descifrado OAEP* y *Firma PSS*) emplean el exponente completo $d$, cuya longitud en bits coincide con el modulo $n$. El tiempo crece aproximadamente de forma cubica $O(b^3)$ respecto al tamano de bits.
> - **Generacion de Claves:** Requiere la busqueda probabilistica de dos primos independientes mediante 40 rondas de Miller-Rabin, siendo la operacion mas exigente a 3072 bits.