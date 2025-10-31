from __future__ import annotations

import json
import math
import secrets
from typing import Dict, Tuple

from .base import EncryptionAlgorithm, EncryptionResult


def _is_prime(candidate: int) -> bool:
    if candidate < 2:
        return False
    if candidate in (2, 3):
        return True
    if candidate % 2 == 0 or candidate % 3 == 0:
        return False
    limit = int(math.isqrt(candidate)) + 1
    for divisor in range(5, limit, 6):
        if candidate % divisor == 0 or candidate % (divisor + 2) == 0:
            return False
    return True


def _generate_prime(min_value: int = 10_000, max_value: int = 50_000) -> int:
    while True:
        candidate = secrets.randbelow(max_value - min_value) + min_value
        if candidate % 2 == 0:
            candidate += 1
        if _is_prime(candidate):
            return candidate


class RSAAlgorithm(EncryptionAlgorithm):
    id = "rsa"
    display_names = {"en": "RSA", "ru": "RSA"}
    descriptions = {
        "en": "Generates an RSA key pair and encrypts the password with the public key.",
        "ru": "Генерирует пару ключей RSA и шифрует пароль открытым ключом.",
    }
    key_hints = {
        "en": "Keys are generated automatically.",
        "ru": "Ключи генерируются автоматически.",
    }

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        p = _generate_prime()
        q = _generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while math.gcd(e, phi) != 1:
            e += 2
        d = pow(e, -1, phi)
        message_int = int.from_bytes(plaintext.encode("utf-8"), "big")
        while message_int >= n:
            p = _generate_prime()
            q = _generate_prime()
            n = p * q
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
        ciphertext = pow(message_int, e, n)
        metadata = {"n": n, "d": d, "e": e}
        return EncryptionResult(ciphertext=str(ciphertext), metadata=metadata)

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        try:
            n = int(metadata["n"])
            d = int(metadata["d"])
            cipher_int = int(ciphertext)
        except (KeyError, ValueError, TypeError):  # pragma: no cover - invalid persisted data
            return False
        message_int = pow(cipher_int, d, n)
        try:
            message_bytes_length = (message_int.bit_length() + 7) // 8
            message_bytes = message_int.to_bytes(message_bytes_length, "big")
            recovered = message_bytes.decode("utf-8")
        except Exception:  # pragma: no cover - unexpected decoding issue
            return False
        return recovered == plaintext


class ElGamalAlgorithm(EncryptionAlgorithm):
    id = "elgamal"
    display_names = {"en": "ElGamal", "ru": "Эль-Гамаль"}
    descriptions = {
        "en": "Implements a simplified ElGamal encryption scheme over integers.",
        "ru": "Реализует упрощенный шифр Эль-Гамаля над целыми числами.",
    }
    key_hints = {
        "en": "Keys are generated automatically.",
        "ru": "Ключи генерируются автоматически.",
    }

    def _generate_parameters(self, message_int: int) -> Tuple[int, int, int, int]:
        p = _generate_prime(20_000, 80_000)
        while p <= message_int:
            p = _generate_prime(20_000, 80_000)
        g = 2
        x = secrets.randbelow(p - 2) + 1
        y = pow(g, x, p)
        return p, g, x, y

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        message_int = int.from_bytes(plaintext.encode("utf-8"), "big")
        p, g, x, y = self._generate_parameters(message_int)
        k = secrets.randbelow(p - 2) + 1
        a = pow(g, k, p)
        b = (pow(y, k, p) * message_int) % p
        ciphertext = json.dumps({"a": a, "b": b})
        metadata = {"p": p, "g": g, "x": x, "y": y}
        return EncryptionResult(ciphertext=ciphertext, metadata=metadata)

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        try:
            payload = json.loads(ciphertext)
            p = int(metadata["p"])
            x = int(metadata["x"])
            a = int(payload["a"])
            b = int(payload["b"])
        except (KeyError, ValueError, TypeError, json.JSONDecodeError):
            return False
        s = pow(a, x, p)
        s_inv = pow(s, -1, p)
        message_int = (b * s_inv) % p
        message_bytes_length = (message_int.bit_length() + 7) // 8
        message_bytes = message_int.to_bytes(message_bytes_length, "big")
        try:
            recovered = message_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return recovered == plaintext
