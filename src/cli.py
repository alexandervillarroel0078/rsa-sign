"""
CLI de RSA-Sign.

Subcomandos:
- keygen: Generacion de pares de claves RSA (1024, 2048, 3072, 4096 bits).
- encrypt / decrypt: Cifrado y descifrado asimetrico con relleno OAEP-SHA256.
- sign / verify: Firma digital RSA-PSS sobre SHA-256 (archivos por streaming).
- attack-fermat: Factorizacion de Fermat y recuperacion de clave privada (demo).
- corrupt: Inversion de un bit en firma o criptograma (demo).
- demo-ataque: maleabilidad textbook, e pequeno, falsificacion con e=1, oraculo OAEP.

Se puede ejecutar como:
    python cli.py ...        (raiz del proyecto)
    python -m src.cli ...
    python src/cli.py ...
"""

import argparse
import sys
from pathlib import Path

# Soporte para "python -m src.cli" (paquete) y "python src/cli.py" (script).
try:
    from .rsa import (
        MIN_PUBLIC_BITS,
        generate_keypair,
        save_public_key,
        load_public_key,
        save_private_key,
        load_private_key,
        encrypt_oaep,
        decrypt_oaep,
        sign_hash,
        verify_hash,
        public_key_fingerprint,
    )
    from .sha256 import sha256, sha256_file
    from .attacks import (
        fermat_attack_rsa,
        generate_weak_fermat_key,
        corrupt_bit,
        demo_maleabilidad,
        demo_e_pequeno,
        demo_falsificacion_e1,
        demo_oraculo_oaep,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.rsa import (
        MIN_PUBLIC_BITS,
        generate_keypair,
        save_public_key,
        load_public_key,
        save_private_key,
        load_private_key,
        encrypt_oaep,
        decrypt_oaep,
        sign_hash,
        verify_hash,
        public_key_fingerprint,
    )
    from src.sha256 import sha256, sha256_file
    from src.attacks import (
        fermat_attack_rsa,
        generate_weak_fermat_key,
        corrupt_bit,
        demo_maleabilidad,
        demo_e_pequeno,
        demo_falsificacion_e1,
        demo_oraculo_oaep,
    )


class CliError(Exception):
    """Error de uso con un mensaje pensado para el usuario (sin traceback)."""


MSG_VERIFICACION_FALLIDA = "[-] VERIFICACION FALLIDA: La firma es invalida o el mensaje fue adulterado."


def _mostrar_huella(pub):
    print(f"    Huella SHA-256 de la clave publica: {public_key_fingerprint(pub)}")


def _hex_a_bytes(texto: str, que: str) -> bytes:
    """Convierte hex a bytes; si no es hex valido lanza CliError con mensaje claro."""
    try:
        return bytes.fromhex(texto.strip())
    except ValueError:
        raise CliError(f"{que} no es hexadecimal valido (solo 0-9, a-f y longitud par).") from None


def _leer_texto(ruta: str) -> str:
    with open(ruta, "r", encoding="utf-8") as f:
        return f.read()


def _resumen_mensaje(args) -> bytes:
    """SHA-256 del mensaje: de --msg (puede ser "") o de --file leido por bloques."""
    if args.msg is not None:
        return sha256(args.msg.encode("utf-8"))
    return sha256_file(args.file)


def cmd_keygen(args):
    if args.bits < MIN_PUBLIC_BITS:
        extra = " y no admite OAEP/PSS-SHA256 (minimo 522 bits)" if args.bits < 522 else ""
        print(f"[!] AVISO: {args.bits} bits es inseguro{extra}. Las claves publicas de menos de "
              f"{MIN_PUBLIC_BITS} bits se rechazan al cargarlas. SOLO DEMOSTRACION.")
    print(f"[*] Generando par de claves RSA de {args.bits} bits...")
    pub, priv = generate_keypair(bits=args.bits)
    n, e = pub
    print(f"[+] Claves generadas exitosamente.")
    print(f"    Modulo n: {hex(n)[:32]}... ({n.bit_length()} bits)")
    print(f"    Exponente e: {e}")
    _mostrar_huella(pub)

    if args.pub:
        save_public_key(pub, args.pub)
        print(f"[+] Clave publica guardada en: {args.pub}")
    if args.priv:
        save_private_key(priv, args.priv)
        print(f"[+] Clave privada guardada en: {args.priv}")


def cmd_encrypt(args):
    pub = load_public_key(args.key)
    _mostrar_huella(pub)
    if args.msg is not None:
        datos = args.msg.encode("utf-8")
    else:
        with open(args.file, "rb") as f:
            datos = f.read()

    criptograma = encrypt_oaep(datos, pub)
    hex_str = criptograma.hex()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(hex_str)
        print(f"[+] Criptograma guardado en: {args.out}")
    else:
        print(f"[+] Criptograma (hex): {hex_str}")


def cmd_decrypt(args):
    priv = load_private_key(args.key)
    texto_hex = args.hex if args.hex is not None else _leer_texto(args.file)
    c_bytes = _hex_a_bytes(texto_hex, "El criptograma")

    try:
        plano = decrypt_oaep(c_bytes, priv)
    except ValueError:
        # Mensaje unico y fijo: no se revela la causa (evita oraculo de relleno).
        raise CliError("Error de descifrado: decryption error") from None

    if args.out:
        with open(args.out, "wb") as f:
            f.write(plano)
        print(f"[+] Mensaje descifrado guardado en: {args.out}")
    else:
        print(f"[+] Mensaje descifrado: {plano.decode('utf-8', errors='replace')}")


def cmd_sign(args):
    priv = load_private_key(args.key)
    firma = sign_hash(_resumen_mensaje(args), priv)
    sig_hex = firma.hex()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(sig_hex)
        print(f"[+] Firma guardada en: {args.out}")
    else:
        print(f"[+] Firma RSA-PSS (hex): {sig_hex}")


def cmd_verify(args):
    pub = load_public_key(args.key)
    _mostrar_huella(pub)
    m_hash = _resumen_mensaje(args)
    sig_hex = args.sig if args.sig is not None else _leer_texto(args.sig_file)

    # Una firma con caracteres no hexadecimales o longitud impar no puede ser
    # valida: se rechaza con el mismo mensaje, sin mostrar el error interno.
    try:
        firma = bytes.fromhex(sig_hex.strip())
    except ValueError:
        raise CliError(MSG_VERIFICACION_FALLIDA[4:]) from None

    if verify_hash(m_hash, firma, pub):
        print("[+] VERIFICACION EXITOSA: La firma es autentica e integra.")
    else:
        raise CliError(MSG_VERIFICACION_FALLIDA[4:])


def cmd_attack_fermat(args):
    print("[!] SOLO DEMOSTRACION: ataque contra claves con primos cercanos.")
    if args.generate_weak:
        print(f"[*] Generando clave debil vulnerable de {args.bits} bits...")
        pub, priv_real = generate_weak_fermat_key(bits=args.bits)
        print(f"[+] Clave debil creada con exito.")
    else:
        if not args.key:
            raise CliError("Debe indicar --key con la clave publica objetivo o --generate-weak.")
        # El atacante acepta cualquier clave (incluso pequena) como objetivo.
        pub = load_public_key(args.key, allow_weak=True)

    print(f"[*] Iniciando ataque de factorizacion de Fermat sobre modulo n...")
    print(f"    n = {pub[0]}")
    print(f"    e = {pub[1]}")

    resultado = fermat_attack_rsa(pub, max_iter=args.max_iter)
    if resultado is None:
        print(f"[-] Ataque terminado: no se factorizo en {args.max_iter} iteraciones (clave no vulnerable a Fermat).")
    else:
        priv_recuperada, (p, q), iteraciones = resultado
        print(f"[+] ATAQUE EXITOSO en {iteraciones} iteraciones!")
        print(f"    p recuperado: {p}")
        print(f"    q recuperado: {q}")
        print(f"    d recuperado: {priv_recuperada[1]}")
        if args.out:
            save_private_key(priv_recuperada, args.out)
            print(f"[+] Clave privada atacada guardada en: {args.out}")


def cmd_corrupt(args):
    datos = _hex_a_bytes(args.hex, "--hex")
    try:
        alterado = corrupt_bit(datos, bit_index=args.bit)
    except (IndexError, ValueError) as err:
        raise CliError(str(err)) from None
    print(f"[+] Original : {datos.hex()}")
    print(f"[+] Alterado (bit {args.bit}): {alterado.hex()}")


def cmd_demo_ataque(args):
    print("[!] RSA textbook / claves debiles: SOLO DEMOSTRACION, INSEGURO.")
    if args.tipo == "maleabilidad":
        r = demo_maleabilidad()
        print(f"[*] El atacante multiplica E({r['a']}) * E({r['b']}) mod n sin conocer d.")
        print(f"[+] Descifrado del criptograma fabricado: {r['descifrado_del_forjado']} (= {r['a']} * {r['b']})")
        print(f"[+] Determinista (mismo mensaje -> mismo criptograma): {r['determinista']}")
        print(f"[+] Ataque de diccionario {{SI, NO}} adivina: {r['diccionario']}")
        print("    Defensa: OAEP (aleatorio y no maleable). Ver 'encrypt'.")
    elif args.tipo == "e-pequeno":
        r = demo_e_pequeno()
        print(f"[*] Clave textbook con e = {r['e']} ({r['n_bits']} bits), mensaje corto sin relleno.")
        print(f"[+] Raiz cubica entera del criptograma: {r['recuperado']!r}  (exito: {r['exito']})")
        print("    Defensa: e = 65537 y relleno OAEP.")
    elif args.tipo == "e1":
        r = demo_falsificacion_e1()
        print(f"[*] Clave publica falsa con e = 1: s^1 = s, la firma falsa cuadra matematicamente: "
              f"{r['cuadra_matematicamente']}")
        print(f"[+] verify la acepta: {r['aceptada']}")
        print(f"[+] Motivo del rechazo: {r['rechazo']}")
    elif args.tipo == "oraculo":
        r = demo_oraculo_oaep()
        print(f"[*] {r['casos']} criptogramas aleatorios y manipulados descifrados.")
        for msg, cnt in r["mensajes"].items():
            print(f"    {cnt:4d} x {msg}")
        print(f"[+] Mensajes de error distintos: {len(r['mensajes'])} (1 = sin oraculo)")


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CLI - Sistema RSA-Sign")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generar par de claves RSA")
    p_keygen.add_argument("--bits", type=int, default=2048,
                          help="Tamano del modulo en bits: 1024, 2048, 3072, 4096 (default 2048)")
    p_keygen.add_argument("--pub", type=str, help="Archivo JSON donde guardar clave publica (ej: clave_publica.json)")
    p_keygen.add_argument("--priv", type=str, help="Archivo JSON donde guardar clave privada (ej: clave_privada.json)")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Cifrar mensaje con RSA-OAEP")
    p_enc.add_argument("--key", type=str, required=True, help="Ruta de clave publica")
    g = p_enc.add_mutually_exclusive_group(required=True)
    g.add_argument("--msg", type=str, help="Texto plano a cifrar (puede ser vacio)")
    g.add_argument("--file", type=str, help="Archivo a cifrar")
    p_enc.add_argument("--out", type=str, help="Archivo de salida")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Descifrar criptograma con RSA-OAEP")
    p_dec.add_argument("--key", type=str, required=True, help="Ruta de clave privada")
    g = p_dec.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex", type=str, help="Texto hexadecimal a descifrar")
    g.add_argument("--file", type=str, help="Archivo hexadecimal a descifrar")
    p_dec.add_argument("--out", type=str, help="Archivo de salida")

    # sign
    p_sign = subparsers.add_parser("sign", help="Firmar documento con RSA-PSS")
    p_sign.add_argument("--key", type=str, required=True, help="Ruta de clave privada")
    g = p_sign.add_mutually_exclusive_group(required=True)
    g.add_argument("--msg", type=str, help="Texto a firmar (puede ser vacio)")
    g.add_argument("--file", type=str, help="Archivo a firmar (se lee por bloques)")
    p_sign.add_argument("--out", type=str, help="Archivo de salida para la firma")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verificar firma digital RSA-PSS")
    p_ver.add_argument("--key", type=str, required=True, help="Ruta de clave publica")
    g = p_ver.add_mutually_exclusive_group(required=True)
    g.add_argument("--msg", type=str, help="Texto original (puede ser vacio)")
    g.add_argument("--file", type=str, help="Archivo original (se lee por bloques)")
    g = p_ver.add_mutually_exclusive_group(required=True)
    g.add_argument("--sig", type=str, help="Firma en hexadecimal")
    g.add_argument("--sig-file", type=str, help="Archivo que contiene la firma hex")

    # attack-fermat
    p_att = subparsers.add_parser("attack-fermat", help="Ataque de factorizacion de Fermat contra RSA (demo)")
    p_att.add_argument("--key", type=str, help="Ruta de clave publica victima")
    p_att.add_argument("--generate-weak", action="store_true", help="Generar automaticamente una clave debil para prueba")
    p_att.add_argument("--bits", type=int, default=1024, help="Bits si se genera clave debil (default 1024)")
    p_att.add_argument("--max-iter", type=int, default=100000, help="Maximo de iteraciones de Fermat (default 100000)")
    p_att.add_argument("--out", type=str, help="Archivo donde guardar la clave privada recuperada")

    # corrupt
    p_corr = subparsers.add_parser("corrupt", help="Invertir 1 bit en firma o criptograma hex (demo)")
    p_corr.add_argument("--hex", type=str, required=True, help="Cadena hexadecimal")
    p_corr.add_argument("--bit", type=int, default=0, help="Indice de bit a invertir (default 0)")

    # demo-ataque
    p_demo = subparsers.add_parser("demo-ataque", help="Demostraciones de ataques (SOLO DEMOSTRACION)")
    p_demo.add_argument("tipo", choices=["maleabilidad", "e-pequeno", "e1", "oraculo"],
                        help="maleabilidad: RSA textbook | e-pequeno: e=3 sin relleno | "
                             "e1: firma falsa con e=1 (rechazada) | oraculo: errores OAEP")
    return parser


COMANDOS = {
    "keygen": cmd_keygen,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "sign": cmd_sign,
    "verify": cmd_verify,
    "attack-fermat": cmd_attack_fermat,
    "corrupt": cmd_corrupt,
    "demo-ataque": cmd_demo_ataque,
}


def main(argv=None) -> int:
    """
    Punto de entrada. Devuelve el codigo de salida (0 = exito, 1 = error).

    Los errores esperables (archivo inexistente, hex invalido, clave invalida,
    mensaje demasiado largo...) se muestran como una linea "[-] ..." sin traceback.
    """
    parser = _construir_parser()
    args = parser.parse_args(argv)
    funcion = COMANDOS.get(args.command)
    if funcion is None:
        parser.print_help()
        return 0
    try:
        funcion(args)
        return 0
    except CliError as err:
        print(f"[-] {err}")
    except FileNotFoundError as err:
        print(f"[-] Archivo no encontrado: {err.filename}" if err.filename else f"[-] {err}")
    except PermissionError as err:
        print(f"[-] Sin permiso para acceder al archivo: {err.filename}")
    except (ValueError, TypeError) as err:
        print(f"[-] Error: {err}")
    except OSError as err:
        print(f"[-] Error de entrada/salida: {err}")
    except KeyboardInterrupt:
        print("\n[-] Cancelado por el usuario.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
