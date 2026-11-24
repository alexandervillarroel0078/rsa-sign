"""
Modulo de Pruebas de Ataque para RSA.

Implementa:
1. Ataque de factorizacion de Fermat contra modulos RSA con primos cercanos (p ~ q).
   - Calculo de raiz cuadrada entera a mano (metodo babilonico / Newton).
   - Comprobacion de cuadrados perfectos.
   - Recuperacion completa de la clave privada d a partir de la clave publica (n, e).
2. Ataque de alteracion de 1 bit en firma digital / mensaje.
   - Demuestra la estricta integridad del esquema RSA-PSS.

Las claves usan el mismo formato que src/rsa.py: publica (n, e) y privada (n, d).
"""

import secrets

from .mathcore import gcd, modexp, modinv
from .primes import generate_prime, is_probable_prime


def isqrt(n: int) -> int:
    """
    Calcula la raiz cuadrada entera de n usando el algoritmo de Newton (metodo babilonico).
    Devuelve el mayor entero s tal que s * s <= n.

    Funciona con enteros de precision arbitraria en tiempo logaritmico.
    """
    if n < 0:
        raise ValueError("No existe raiz cuadrada real para enteros negativos.")
    if n == 0:
        return 0

    # Estimacion inicial con desplazamiento de bits: 2^ceil(bits / 2)
    x = 1 << ((n.bit_length() + 1) // 2)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y


def is_square(k: int) -> tuple:
    """
    Determina si un entero k es un cuadrado perfecto.

    :param k: Entero a verificar.
    :return: (True, raiz) si k == raiz^2, o (False, 0) en caso contrario.
    """
    if k < 0:
        return False, 0
    r = isqrt(k)
    return (r * r == k), r


def _fermat_search(n: int, max_iter: int):
    """
    Nucleo del metodo de Fermat (compartido por fermat_factor y fermat_attack_rsa).

    Principio matematico:
    Todo impar se expresa como n = a^2 - b^2 = (a - b)(a + b).
    Si los factores p y q son proximos, 'a' estara muy cerca de ceil(sqrt(n)).
    Se prueba a = ceil(sqrt(n)), ceil(sqrt(n)) + 1, ... comprobando si a^2 - n es cuadrado.

    :return: (p, q, iteraciones) con p <= q, o None si no se hallo en max_iter.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("n debe ser un entero impar y positivo.")

    # a inicial = ceil(sqrt(n))
    a = isqrt(n)
    if a * a < n:
        a += 1

    for it in range(1, max_iter + 1):
        es_cuad, b = is_square(a * a - n)
        if es_cuad:
            p, q = a - b, a + b
            if p > 1 and q > 1:
                return (min(p, q), max(p, q), it)
        a += 1
    return None


def fermat_factor(n: int, max_iter: int = 100000):
    """
    Factoriza un numero compuesto impar n = p * q usando el metodo de Fermat.

    :param n: Modulo impar a factorizar.
    :param max_iter: Numero maximo de iteraciones.
    :return: Tupla (p, q) con p <= q, o None si no se hallo factor en el limite dado.
    """
    r = _fermat_search(n, max_iter)
    return None if r is None else (r[0], r[1])


def fermat_attack_rsa(pub_key: tuple, max_iter: int = 100000):
    """
    Ejecuta el ataque de Fermat contra una clave publica RSA (n, e).

    Si los primos p y q fueron generados demasiado cerca, el ataque factoriza n,
    calcula phi(n) = (p - 1)*(q - 1) y deriva la clave privada d = e^(-1) mod phi(n).

    :param pub_key: Clave publica objetivo (n, e).
    :param max_iter: Limite de iteraciones de Fermat.
    :return: Tupla ((n, d), (p, q), iteraciones_realizadas) o None si el ataque falla.
    """
    n, e = pub_key
    r = _fermat_search(n, max_iter)
    if r is None:
        return None
    p, q, it = r
    d = modinv(e, (p - 1) * (q - 1))
    return (n, d), (p, q), it


def generate_weak_fermat_key(bits: int = 512, e: int = 65537) -> tuple:
    """
    Genera deliberadamente un par de claves RSA debil con primos p y q muy cercanos,
    vulnerable al ataque de factorizacion de Fermat. SOLO DEMOSTRACION.

    :param bits: Longitud en bits del modulo n.
    :param e: Exponente publico.
    :return: ((n, e), (n, d)), mismo formato que rsa.generate_keypair.
    """
    half = bits // 2
    while True:
        # Generamos p normalmente
        p = generate_prime(half)

        # Buscamos q inmediatamente posterior a p para que |p - q| sea minusculo
        q = p + 2
        while not is_probable_prime(q):
            q += 2

        phi = (p - 1) * (q - 1)
        # e debe ser coprimo con phi para que exista d = e^(-1) mod phi
        if gcd(e, phi) == 1:
            break

    n = p * q
    d = modinv(e, phi)
    return (n, e), (n, d)


def corrupt_bit(data: bytes, bit_index: int = 0) -> bytes:
    """
    Invierte exactamente 1 bit en la posicion indicada de una secuencia de bytes.

    Se utiliza en las pruebas de seguridad para demostrar que una firma digital
    RSA-PSS con un solo bit alterado (en el mensaje o en la firma) es inmediatamente
    rechazada por el algoritmo de verificacion.

    :param data: Datos originales en bytes.
    :param bit_index: Posicion del bit a invertir (0-indexed).
    :return: Nuevos bytes con ese unico bit invertido.
    """
    if not data:
        raise ValueError("La secuencia de datos no puede estar vacia.")

    byte_idx = bit_index // 8
    bit_offset = bit_index % 8

    if byte_idx >= len(data):
        raise IndexError(f"bit_index={bit_index} fuera de rango para {len(data)} bytes.")

    modificado = bytearray(data)
    modificado[byte_idx] ^= (1 << bit_offset)
    return bytes(modificado)


# ---------------------------------------------------------------------------
# Demostraciones para la defensa oral
# ---------------------------------------------------------------------------

def iroot(x: int, k: int) -> int:
    """
    Raiz k-esima entera: mayor r tal que r^k <= x (busqueda binaria).

    Se usa en el ataque de e pequeno: si m^e < n, entonces c = m^e sin
    reduccion modular y m = iroot(c, e).
    """
    if x < 0 or k < 1:
        raise ValueError("x debe ser >= 0 y k >= 1.")
    lo, hi = 0, 1 << (x.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def demo_maleabilidad(bits: int = 1024) -> dict:
    """
    RSA textbook es maleable: E(a) * E(b) mod n = E(a * b mod n).

    Un atacante que solo ve E(a) y E(b) fabrica un criptograma valido de a*b
    sin conocer a, b ni d. Ademas, el textbook es determinista: cifrando
    candidatos con la clave publica se adivina el mensaje.
    """
    from .rsa import decrypt, encrypt, generate_keypair

    pub, priv = generate_keypair(bits)
    n = pub[0]
    k = (n.bit_length() + 7) // 8
    a, b = 5, 7
    ca = int.from_bytes(encrypt(bytes([a]), pub), "big")
    cb = int.from_bytes(encrypt(bytes([b]), pub), "big")
    c_forjado = (ca * cb) % n
    producto = int.from_bytes(decrypt(c_forjado.to_bytes(k, "big"), priv), "big")

    objetivo = encrypt(b"NO", pub)
    adivinado = [w for w in (b"SI", b"NO") if encrypt(w, pub) == objetivo]
    return {"a": a, "b": b, "descifrado_del_forjado": producto,
            "determinista": encrypt(b"SI", pub) == encrypt(b"SI", pub),
            "diccionario": adivinado}


def demo_e_pequeno(bits: int = 1024, mensaje: bytes = b"clave AES 16B!!!") -> dict:
    """
    Con e = 3 y SIN relleno, un mensaje corto cumple m^3 < n: el criptograma
    es m^3 "en los enteros" y basta una raiz cubica para recuperarlo.
    El proyecto usa e = 65537 y OAEP, que evitan este ataque.
    """
    from .rsa import encrypt

    e = 3
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p != q and gcd(e, (p - 1) * (q - 1)) == 1:
            break
    n = p * q
    c = int.from_bytes(encrypt(mensaje, (n, e), allow_weak=True), "big")
    m = iroot(c, e)
    recuperado = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return {"n_bits": n.bit_length(), "e": e, "mensaje": mensaje,
            "recuperado": recuperado, "exito": recuperado == mensaje}


def demo_falsificacion_e1(bits: int = 1024, mensaje: bytes = b"Pagar 1000000 Bs") -> dict:
    """
    Con una clave publica falsa (n, e = 1), s^e = s: el atacante pone como
    firma el propio bloque EMSA-PSS y la verificacion matematica cuadra sin
    usar la clave privada. validate_public_key rechaza e = 1 antes de verificar.
    """
    from .pss import emsa_pss_encode
    from .rsa import generate_keypair, verify
    from .sha256 import sha256

    pub, _ = generate_keypair(bits)
    n = pub[0]
    k = (n.bit_length() + 7) // 8
    em = emsa_pss_encode(sha256(mensaje), n.bit_length() - 1)
    firma_falsa = int.from_bytes(em, "big").to_bytes(k, "big")
    cuadra_sin_validar = modexp(int.from_bytes(firma_falsa, "big"), 1, n) == int.from_bytes(em, "big")
    try:
        aceptada = verify(mensaje, firma_falsa, (n, 1))
        error = None
    except ValueError as err:
        aceptada = False
        error = str(err)
    return {"cuadra_matematicamente": cuadra_sin_validar, "aceptada": aceptada, "rechazo": error}


def demo_oraculo_oaep(bits: int = 1024, muestras: int = 200) -> dict:
    """
    Descifra criptogramas aleatorios y manipulados y cuenta los mensajes de
    error distintos. Con un oraculo habria varios (primer byte, lHash, ...);
    ahora debe haber exactamente uno: "decryption error".
    """
    from .rsa import decrypt_oaep, encrypt_oaep, generate_keypair

    pub, priv = generate_keypair(bits)
    n = pub[0]
    k = (n.bit_length() + 7) // 8
    casos = [secrets.randbelow(n).to_bytes(k, "big") for _ in range(muestras)]
    legitimo = bytearray(encrypt_oaep(b"mensaje legitimo", pub))
    for pos in (0, 1, k // 2, k - 1):
        alterado = bytearray(legitimo)
        alterado[pos] ^= 0x01
        casos.append(bytes(alterado))
    errores: dict = {}
    for c in casos:
        try:
            decrypt_oaep(c, priv)
            clave = "(descifro sin error)"
        except ValueError as err:
            clave = str(err)
        errores[clave] = errores.get(clave, 0) + 1
    return {"casos": len(casos), "mensajes": errores}


def demo_timing(bits: int = 2048, reps: int = 10) -> dict:
    """
    Tiempos de la operacion privada c^d mod n:
    - con CRT y sin CRT (misma clave, ambas con blinding);
    - square-and-multiply con un exponente de pocos bits a 1 frente a uno con
      todos los bits a 1: el tiempo depende del exponente, por eso un atacante
      que mide tiempos aprende sobre d. El blinding aleatoriza la base para que
      el atacante no controle lo que se exponencia.
    """
    import time
    from .rsa import RSAPrivateKey, generate_keypair, rsa_private_op

    _, priv = generate_keypair(bits)
    n = priv[0]
    sin_crt = RSAPrivateKey(priv[0], priv[1], e=priv.e)
    c = secrets.randbelow(n)

    def medir(func):
        t0 = time.perf_counter()
        for _ in range(reps):
            func()
        return (time.perf_counter() - t0) / reps

    t_crt = medir(lambda: rsa_private_op(c, priv))
    t_sin = medir(lambda: rsa_private_op(c, sin_crt))
    exp_ligero = (1 << (bits - 1)) | 1
    exp_pesado = (1 << bits) - 1
    t_ligero = medir(lambda: modexp(c, exp_ligero, n))
    t_pesado = medir(lambda: modexp(c, exp_pesado, n))
    return {"bits": bits, "reps": reps, "con_crt_s": t_crt, "sin_crt_s": t_sin,
            "speedup": t_sin / t_crt, "exp_2_unos_s": t_ligero, "exp_todo_unos_s": t_pesado}
