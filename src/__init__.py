"""
Paquete rsa-sign: primitivas criptograficas implementadas a mano.

Modulos:
- sha256    SHA-256 (FIPS 180-4), incremental y por archivo.
- mathcore  gcd, Euclides extendido, inverso modular, exponenciacion modular.
- primes    Miller-Rabin y generacion de primos.
- oaep      MGF1 y relleno OAEP (RFC 8017).
- pss       Relleno EMSA-PSS (RFC 8017).
- rsa       Claves, cifrado OAEP, firma PSS, persistencia y validacion.
- attacks   Ataques y demostraciones (Fermat, textbook, e=1, oraculo).
La CLI (src.cli), la GUI (src.gui) y el benchmark (src.benchmark) no se
importan aqui para no cargar tkinter ni argparse al usar la libreria.
"""

from .sha256 import Sha256, sha256, sha256_file, sha256_hex
from .mathcore import egcd, gcd, modexp, modinv
from .primes import generate_prime, is_probable_prime
from .oaep import DECRYPTION_ERROR, mgf1, oaep_decode, oaep_encode
from .pss import emsa_pss_encode, emsa_pss_verify
from .rsa import (
    E_DEFAULT,
    MIN_PUBLIC_BITS,
    decrypt,
    decrypt_oaep,
    encrypt,
    encrypt_oaep,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    save_private_key,
    save_public_key,
    sign,
    sign_hash,
    validate_public_key,
    verify,
    verify_hash,
)
from .attacks import (
    corrupt_bit,
    fermat_attack_rsa,
    fermat_factor,
    generate_weak_fermat_key,
)

__all__ = [
    "Sha256", "sha256", "sha256_file", "sha256_hex",
    "egcd", "gcd", "modexp", "modinv",
    "generate_prime", "is_probable_prime",
    "DECRYPTION_ERROR", "mgf1", "oaep_decode", "oaep_encode",
    "emsa_pss_encode", "emsa_pss_verify",
    "E_DEFAULT", "MIN_PUBLIC_BITS", "decrypt", "decrypt_oaep", "encrypt", "encrypt_oaep",
    "generate_keypair", "load_private_key", "load_public_key", "public_key_fingerprint",
    "save_private_key", "save_public_key", "sign", "sign_hash", "validate_public_key",
    "verify", "verify_hash",
    "corrupt_bit", "fermat_attack_rsa", "fermat_factor", "generate_weak_fermat_key",
]
