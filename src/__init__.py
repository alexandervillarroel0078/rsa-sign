"""
Paquete rsa-sign: Primitivas criptograficas y sistema de firma digital implementados a mano.
"""

from .sha256 import sha256, sha256_hex
from .mathcore import egcd, modinv, modexp, gcd
from .primes import generate_prime, is_probable_prime
from .rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    generate_keypair,
    save_public_key,
    load_public_key,
    save_private_key,
    load_private_key,
    rsa_encrypt_int,
    rsa_decrypt_int,
    bytes_to_int,
    int_to_bytes,
)
from .mgf1 import mgf1, xor_bytes
from .oaep import oaep_encode, oaep_decode, rsa_encrypt_oaep, rsa_decrypt_oaep
from .pss import (
    emsa_pss_encode,
    emsa_pss_verify,
    constant_time_compare,
    rsa_sign_pss,
    rsa_verify_pss,
)
from .attacks import (
    isqrt,
    is_square,
    fermat_factor,
    fermat_attack_rsa,
    generate_weak_fermat_key,
    corrupt_bit,
)

__all__ = [
    # SHA-256
    "sha256",
    "sha256_hex",
    # Mathcore
    "egcd",
    "modinv",
    "modexp",
    "gcd",
    # Primes
    "generate_prime",
    "is_probable_prime",
    # RSA
    "RSAPublicKey",
    "RSAPrivateKey",
    "generate_keypair",
    "save_public_key",
    "load_public_key",
    "save_private_key",
    "load_private_key",
    "rsa_encrypt_int",
    "rsa_decrypt_int",
    "bytes_to_int",
    "int_to_bytes",
    # MGF1
    "mgf1",
    "xor_bytes",
    # OAEP
    "oaep_encode",
    "oaep_decode",
    "rsa_encrypt_oaep",
    "rsa_decrypt_oaep",
    # PSS
    "emsa_pss_encode",
    "emsa_pss_verify",
    "constant_time_compare",
    "rsa_sign_pss",
    "rsa_verify_pss",
    # Attacks
    "isqrt",
    "is_square",
    "fermat_factor",
    "fermat_attack_rsa",
    "generate_weak_fermat_key",
    "corrupt_bit",
]
