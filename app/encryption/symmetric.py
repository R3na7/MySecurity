from __future__ import annotations

import itertools
from typing import Dict

from .base import EncryptionAlgorithm, EncryptionResult

ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = ALPHABET_LOWER.upper()


def _shift_character(ch: str, shift: int) -> str:
    if ch in ALPHABET_LOWER:
        idx = ALPHABET_LOWER.index(ch)
        return ALPHABET_LOWER[(idx + shift) % 26]
    if ch in ALPHABET_UPPER:
        idx = ALPHABET_UPPER.index(ch)
        return ALPHABET_UPPER[(idx + shift) % 26]
    return ch


class CaesarCipherAlgorithm(EncryptionAlgorithm):
    id = "caesar"
    display_names = {"en": "Caesar cipher", "ru": "Шифр Цезаря"}
    descriptions = {
        "en": "Classic shift cipher with a numeric key.",
        "ru": "Классический сдвиговый шифр с числовым ключом.",
    }
    key_hints = {
        "en": "Enter any integer shift value (e.g. 3).",
        "ru": "Введите целое число для сдвига (например, 3).",
    }

    def requires_key(self) -> bool:
        return True

    def normalize_key(self, raw_value: str | None) -> int:
        if raw_value is None:
            raise ValueError("Shift value is required")
        try:
            return int(raw_value) % 26
        except ValueError as exc:  # pragma: no cover - invalid user input
            raise ValueError("invalid_shift") from exc

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        shift = int(key)
        ciphertext = "".join(_shift_character(ch, shift) for ch in plaintext)
        return EncryptionResult(ciphertext=ciphertext, metadata={"shift": shift})

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        shift = int(metadata.get("shift", 0))
        decrypted = "".join(_shift_character(ch, -shift) for ch in ciphertext)
        return decrypted == plaintext


class VigenereCipherAlgorithm(EncryptionAlgorithm):
    id = "vigenere"
    display_names = {"en": "Vigenère cipher", "ru": "Шифр Виженера"}
    descriptions = {
        "en": "Poly-alphabetic cipher that repeats a keyword.",
        "ru": "Многоалфавитный шифр, использующий ключевое слово.",
    }
    key_hints = {
        "en": "Enter a keyword consisting of letters.",
        "ru": "Введите ключевое слово, состоящее из букв.",
    }

    def requires_key(self) -> bool:
        return True

    def normalize_key(self, raw_value: str | None) -> str:
        if not raw_value:
            raise ValueError("keyword_required")
        keyword = "".join(ch.lower() for ch in raw_value if ch.isalpha())
        if not keyword:
            raise ValueError("keyword_required")
        return keyword

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        keyword = str(key)
        ciphertext_chars: list[str] = []
        keyword_cycle = itertools.cycle(keyword)
        for ch in plaintext:
            if ch.isalpha():
                shift = ord(next(keyword_cycle)) - ord("a")
                ciphertext_chars.append(_shift_character(ch, shift))
            else:
                ciphertext_chars.append(ch)
        ciphertext = "".join(ciphertext_chars)
        return EncryptionResult(ciphertext=ciphertext, metadata={"keyword": keyword})

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        keyword = str(metadata.get("keyword", ""))
        if not keyword:
            return False
        keyword_cycle = itertools.cycle(keyword)
        decrypted: list[str] = []
        for ch in ciphertext:
            if ch.isalpha():
                shift = ord(next(keyword_cycle)) - ord("a")
                decrypted.append(_shift_character(ch, -shift))
            else:
                decrypted.append(ch)
        return "".join(decrypted) == plaintext


class XorCipherAlgorithm(EncryptionAlgorithm):
    id = "xor"
    display_names = {"en": "XOR cipher", "ru": "XOR-шифр"}
    descriptions = {
        "en": "Applies a repeating XOR mask over the password.",
        "ru": "Применяет повторяющуюся XOR-маску к паролю.",
    }
    key_hints = {
        "en": "Enter any passphrase. It will be repeated over the password.",
        "ru": "Введите любую парольную фразу. Она будет повторяться по паролю.",
    }

    def requires_key(self) -> bool:
        return True

    def normalize_key(self, raw_value: str | None) -> bytes:
        if not raw_value:
            raise ValueError("xor_key_required")
        return raw_value.encode("utf-8")

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        key_bytes = bytes(key)
        data = plaintext.encode("utf-8")
        result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return EncryptionResult(ciphertext=result.hex(), metadata={"key": key_bytes.hex()})

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        key_hex = metadata.get("key")
        if not isinstance(key_hex, str):
            return False
        key_bytes = bytes.fromhex(key_hex)
        cipher_bytes = bytes.fromhex(ciphertext)
        plain_bytes = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes))
        return plain_bytes.decode("utf-8") == plaintext


class AtbashCipherAlgorithm(EncryptionAlgorithm):
    id = "atbash"
    display_names = {"en": "Atbash cipher", "ru": "Шифр Атбаш"}
    descriptions = {
        "en": "Mirrors the alphabet in reverse order.",
        "ru": "Заменяет каждую букву на противоположную в алфавите.",
    }
    key_hints = {"en": "Does not require a key.", "ru": "Ключ не требуется."}

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        ciphertext = "".join(self._transform_char(ch) for ch in plaintext)
        return EncryptionResult(ciphertext=ciphertext, metadata={})

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        decrypted = "".join(self._transform_char(ch) for ch in ciphertext)
        return decrypted == plaintext

    @staticmethod
    def _transform_char(ch: str) -> str:
        if ch in ALPHABET_LOWER:
            idx = ALPHABET_LOWER.index(ch)
            return ALPHABET_LOWER[-(idx + 1)]
        if ch in ALPHABET_UPPER:
            idx = ALPHABET_UPPER.index(ch)
            return ALPHABET_UPPER[-(idx + 1)]
        return ch


class ReverseCipherAlgorithm(EncryptionAlgorithm):
    id = "reverse"
    display_names = {"en": "Reverse cipher", "ru": "Обратный шифр"}
    descriptions = {
        "en": "Stores the password reversed and wrapped with markers.",
        "ru": "Сохраняет пароль в перевернутом виде с маркерами.",
    }
    key_hints = {
        "en": "Does not require a key.",
        "ru": "Ключ не требуется.",
    }

    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        ciphertext = f"@@{plaintext[::-1]}@@"
        return EncryptionResult(ciphertext=ciphertext, metadata={})

    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        if not ciphertext.startswith("@@") or not ciphertext.endswith("@@"):
            return False
        reversed_plain = ciphertext[2:-2][::-1]
        return reversed_plain == plaintext
