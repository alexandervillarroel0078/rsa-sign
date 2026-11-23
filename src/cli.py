"""
CLI de Respaldo para el sistema RSA-Sign.

Permite ejecutar por linea de comandos:
- keygen: Generacion de pares de claves RSA (512, 1024, 2048 bits).
- encrypt: Cifrado asimetrico con relleno OAEP.
- decrypt: Descifrado asimetrico con relleno OAEP.
- sign: Firma digital probabilistica con relleno PSS sobre SHA-256.
- verify: Verificacion de firma digital con comparacion en tiempo constante.
- attack-fermat: Factorizacion de Fermat y recuperacion de clave privada.
- corrupt: Inversion de un bit en firma o criptograma para demostracion de ataques.
"""

import argparse
import os
import sys

from .rsa import (
    generate_keypair,
    save_public_key,
    load_public_key,
    save_private_key,
    load_private_key,
)
from .oaep import rsa_encrypt_oaep, rsa_decrypt_oaep
from .pss import rsa_sign_pss, rsa_verify_pss
from .attacks import fermat_attack_rsa, generate_weak_fermat_key, corrupt_bit


def cmd_keygen(args):
    print(f"[*] Generando par de claves RSA de {args.bits} bits...")
    pub, priv = generate_keypair(bits=args.bits)
    print(f"[+] Claves generadas exitosamente.")
    print(f"    Modulo n: {hex(pub.n)[:32]}... ({pub.bit_length()} bits)")
    print(f"    Exponente e: {pub.e}")

    if args.pub:
        save_public_key(pub, args.pub)
        print(f"[+] Clave publica guardada en: {args.pub}")
    if args.priv:
        save_private_key(priv, args.priv)
        print(f"[+] Clave privada guardada en: {args.priv}")


def cmd_encrypt(args):
    pub = load_public_key(args.key)
    if args.msg:
        datos = args.msg.encode("utf-8")
    elif args.file:
        with open(args.file, "rb") as f:
            datos = f.read()
    else:
        print("[-] Debe especificar --msg o --file.")
        sys.exit(1)

    criptograma = rsa_encrypt_oaep(datos, pub)
    hex_str = criptograma.hex()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(hex_str)
        print(f"[+] Criptograma guardado en: {args.out}")
    else:
        print(f"[+] Criptograma (hex): {hex_str}")


def cmd_decrypt(args):
    priv = load_private_key(args.key)
    if args.hex:
        c_bytes = bytes.fromhex(args.hex.strip())
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            c_bytes = bytes.fromhex(f.read().strip())
    else:
        print("[-] Debe especificar --hex o --file.")
        sys.exit(1)

    try:
        plano = rsa_decrypt_oaep(c_bytes, priv)
        texto = plano.decode("utf-8", errors="replace")
        if args.out:
            with open(args.out, "wb") as f:
                f.write(plano)
            print(f"[+] Mensaje descifrado guardado en: {args.out}")
        else:
            print(f"[+] Mensaje descifrado: {texto}")
    except ValueError as e:
        print(f"[-] Error en el descifrado OAEP: {e}")
        sys.exit(1)


def cmd_sign(args):
    priv = load_private_key(args.key)
    if args.msg:
        datos = args.msg.encode("utf-8")
    elif args.file:
        with open(args.file, "rb") as f:
            datos = f.read()
    else:
        print("[-] Debe especificar --msg o --file.")
        sys.exit(1)

    firma = rsa_sign_pss(datos, priv)
    sig_hex = firma.hex()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(sig_hex)
        print(f"[+] Firma guardada en: {args.out}")
    else:
        print(f"[+] Firma RSA-PSS (hex): {sig_hex}")


def cmd_verify(args):
    pub = load_public_key(args.key)
    if args.msg:
        datos = args.msg.encode("utf-8")
    elif args.file:
        with open(args.file, "rb") as f:
            datos = f.read()
    else:
        print("[-] Debe especificar --msg o --file para el mensaje.")
        sys.exit(1)

    if args.sig:
        firma = bytes.fromhex(args.sig.strip())
    elif args.sig_file:
        with open(args.sig_file, "r", encoding="utf-8") as f:
            firma = bytes.fromhex(f.read().strip())
    else:
        print("[-] Debe especificar --sig o --sig-file para la firma.")
        sys.exit(1)

    valida = rsa_verify_pss(datos, firma, pub)
    if valida:
        print("[+] VERIFICACION EXITOSA: La firma es autentica e integra.")
    else:
        print("[-] VERIFICACION FALLIDA: La firma es invalida o el mensaje fue adulterado.")
        sys.exit(1)


def cmd_attack_fermat(args):
    if args.generate_weak:
        print(f"[*] Generando clave debil vulnerable de {args.bits} bits...")
        pub, priv_real = generate_weak_fermat_key(bits=args.bits)
        print(f"[+] Clave debil creada con exito.")
    else:
        if not args.key:
            print("[-] Debe indicar --key con la clave publica objetivo o --generate-weak.")
            sys.exit(1)
        pub = load_public_key(args.key)

    print(f"[*] Iniciando ataque de factorizacion de Fermat sobre modulo n...")
    print(f"    n = {pub.n}")
    print(f"    e = {pub.e}")

    resultado = fermat_attack_rsa(pub, max_iter=args.max_iter)
    if resultado is None:
        print(f"[-] Ataque terminado: no se factorizo en {args.max_iter} iteraciones (clave no vulnerable a Fermat).")
    else:
        priv_recuperada, iteraciones = resultado
        print(f"[+] ATAQUE EXITOSO en {iteraciones} iteraciones!")
        print(f"    p recuperado: {priv_recuperada.p}")
        print(f"    q recuperado: {priv_recuperada.q}")
        print(f"    d recuperado: {priv_recuperada.d}")
        if args.out:
            save_private_key(priv_recuperada, args.out)
            print(f"[+] Clave privada atacada guardada en: {args.out}")


def cmd_corrupt(args):
    if not args.hex:
        print("[-] Debe indicar --hex con los bytes de entrada.")
        sys.exit(1)

    datos = bytes.fromhex(args.hex.strip())
    alterado = corrupt_bit(datos, bit_index=args.bit)
    print(f"[+] Original : {datos.hex()}")
    print(f"[+] Alterado (bit {args.bit}): {alterado.hex()}")


def main():
    parser = argparse.ArgumentParser(description="CLI de Respaldo - Sistema RSA-Sign")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generar par de claves RSA")
    p_keygen.add_argument("--bits", type=int, default=1024, help="Tamano del modulo en bits (default 1024)")
    p_keygen.add_argument("--pub", type=str, help="Archivo donde guardar clave publica (ej: pub.pem)")
    p_keygen.add_argument("--priv", type=str, help="Archivo donde guardar clave privada (ej: priv.pem)")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Cifrar mensaje con RSA-OAEP")
    p_enc.add_argument("--key", type=str, required=True, help="Ruta de clave publica")
    p_enc.add_argument("--msg", type=str, help="Texto plano a cifrar")
    p_enc.add_argument("--file", type=str, help="Archivo a cifrar")
    p_enc.add_argument("--out", type=str, help="Archivo de salida")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Descifrar criptograma con RSA-OAEP")
    p_dec.add_argument("--key", type=str, required=True, help="Ruta de clave privada")
    p_dec.add_argument("--hex", type=str, help="Texto hexadecimal a descifrar")
    p_dec.add_argument("--file", type=str, help="Archivo hexadecimal a descifrar")
    p_dec.add_argument("--out", type=str, help="Archivo de salida")

    # sign
    p_sign = subparsers.add_parser("sign", help="Firmar documento con RSA-PSS")
    p_sign.add_argument("--key", type=str, required=True, help="Ruta de clave privada")
    p_sign.add_argument("--msg", type=str, help="Texto a firmar")
    p_sign.add_argument("--file", type=str, help="Archivo a firmar")
    p_sign.add_argument("--out", type=str, help="Archivo de salida para la firma")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verificar firma digital RSA-PSS")
    p_ver.add_argument("--key", type=str, required=True, help="Ruta de clave publica")
    p_ver.add_argument("--msg", type=str, help="Texto original")
    p_ver.add_argument("--file", type=str, help="Archivo original")
    p_ver.add_argument("--sig", type=str, help="Firma en hexadecimal")
    p_ver.add_argument("--sig-file", type=str, help="Archivo que contiene la firma hex")

    # attack-fermat
    p_att = subparsers.add_parser("attack-fermat", help="Ataque de factorizacion de Fermat contra RSA")
    p_att.add_argument("--key", type=str, help="Ruta de clave publica victima")
    p_att.add_argument("--generate-weak", action="store_true", help="Generar automaticamente una clave debil para prueba")
    p_att.add_argument("--bits", type=int, default=1024, help="Bits si se genera clave debil (default 1024)")
    p_att.add_argument("--max-iter", type=int, default=100000, help="Maximo de iteraciones de Fermat (default 100000)")
    p_att.add_argument("--out", type=str, help="Archivo donde guardar la clave privada recuperada")

    # corrupt
    p_corr = subparsers.add_parser("corrupt", help="Invertir 1 bit en firma o criptograma hex")
    p_corr.add_argument("--hex", type=str, required=True, help="Cadena hexadecimal")
    p_corr.add_argument("--bit", type=int, default=0, help="Indice de bit a invertir (default 0)")

    args = parser.parse_args()
    if args.command == "keygen":
        cmd_keygen(args)
    elif args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "attack-fermat":
        cmd_attack_fermat(args)
    elif args.command == "corrupt":
        cmd_corrupt(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
