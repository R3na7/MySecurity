from __future__ import annotations

from typing import Dict, Iterable, List

from .asymmetric import ElGamalAlgorithm, RSAAlgorithm
from .base import EncryptionAlgorithm, EncryptionResult
from .symmetric import (
    AtbashCipherAlgorithm,
    CaesarCipherAlgorithm,
    ReverseCipherAlgorithm,
    VigenereCipherAlgorithm,
    XorCipherAlgorithm,
)


class EncryptionManager:
    """Registry and facade for the available encryption algorithms."""

    def __init__(self) -> None:
        self._algorithms: Dict[str, EncryptionAlgorithm] = {}

    def register(self, algorithm: EncryptionAlgorithm) -> None:
        self._algorithms[algorithm.id] = algorithm

    def get(self, algorithm_id: str) -> EncryptionAlgorithm:
        return self._algorithms[algorithm_id]

    def all(self) -> Iterable[EncryptionAlgorithm]:
        return self._algorithms.values()

    def encrypt_password(
        self, algorithm_id: str, plaintext: str, raw_key: str | None
    ) -> EncryptionResult:
        algorithm = self._algorithms[algorithm_id]
        key = algorithm.normalize_key(raw_key) if raw_key or algorithm.requires_key() else None
        return algorithm.encrypt(plaintext, key)

    def verify_password(
        self,
        algorithm_id: str,
        plaintext: str,
        ciphertext: str,
        metadata: Dict[str, object],
    ) -> bool:
        algorithm = self._algorithms[algorithm_id]
        return algorithm.verify(plaintext, ciphertext, metadata)

    def as_choices(self, language: str) -> List[Dict[str, str]]:
        return [
            {
                "id": algorithm.id,
                "name": algorithm.get_display_name(language),
                "description": algorithm.get_description(language),
                "hint": algorithm.get_key_hint(language),
                "requires_key": algorithm.requires_key(),
            }
            for algorithm in self._algorithms.values()
        ]


def build_manager() -> EncryptionManager:
    manager = EncryptionManager()
    manager.register(CaesarCipherAlgorithm())
    manager.register(VigenereCipherAlgorithm())
    manager.register(XorCipherAlgorithm())
    manager.register(AtbashCipherAlgorithm())
    manager.register(ReverseCipherAlgorithm())
    manager.register(RSAAlgorithm())
    manager.register(ElGamalAlgorithm())
    return manager


manager = build_manager()
