from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict


@dataclass
class EncryptionResult:
    ciphertext: str
    metadata: Dict[str, object]


class EncryptionAlgorithm(ABC):
    """Abstract base class for password encryption algorithms."""

    id: str
    display_names: Dict[str, str]
    descriptions: Dict[str, str]
    key_hints: Dict[str, str]

    def __init__(self) -> None:
        if not getattr(self, "id", None):  # pragma: no cover - defensive programming
            raise ValueError("Algorithm must define an identifier")

    def get_display_name(self, language: str) -> str:
        return self.display_names.get(language, self.display_names.get("en", self.id))

    def get_description(self, language: str) -> str:
        return self.descriptions.get(language, self.descriptions.get("en", ""))

    def get_key_hint(self, language: str) -> str:
        return self.key_hints.get(language, self.key_hints.get("en", ""))

    def requires_key(self) -> bool:
        return False

    def normalize_key(self, raw_value: str | None) -> object | None:
        return raw_value

    @abstractmethod
    def encrypt(self, plaintext: str, key: object | None) -> EncryptionResult:
        raise NotImplementedError

    @abstractmethod
    def verify(self, plaintext: str, ciphertext: str, metadata: Dict[str, object]) -> bool:
        raise NotImplementedError
