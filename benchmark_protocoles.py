#!/usr/bin/env python3
"""Mesure trois protocoles d'autorisation d'un KMS auprès d'un HSM artificiel.

Le programme mesure l'accès complet à un fichier : lecture dans un stockage
artificiel, obtention de la CEK auprès du HSM, puis déchiffrement AES-GCM par le
KMS. Aucun délai artificiel n'est ajouté.

Ce prototype sert à comparer les chemins critiques. Il ne constitue ni une
implémentation de production, ni une validation de sécurité des protocoles.

Installation et exécution :
    python -m pip install cryptography
    python benchmark_protocoles.py
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import random
import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


# Nombre de mesures effectuées pour chaque protocole.
ITERATIONS = 10_000

# Nombre d'exécutions préalables non mesurées. Elles chargent les fonctions et
# limitent l'influence du démarrage de Python sur les résultats.
WARMUP = 100

# Taille du fichier testé en kibioctets. 1024 KiB correspondent à 1 Mio.
FILE_SIZE_KIB = 1024

# Valeur utilisée pour générer les mêmes données aléatoires à chaque exécution.
# Elle rend les campagnes de mesures comparables.
SEED = 31082026

PROTOCOLS = ("relay", "precompute", "masked")
LABELS = {
    "relay": "Relais par le client",
    "precompute": "Précalcul avec confirmation",
    "masked": "Réponse masquée",
}


@dataclass(frozen=True)
class FileRecord:
    ciphertext: bytes
    nonce: bytes
    wrapped_cek: bytes


@dataclass(frozen=True)
class Operation:
    request_id: int
    wrapped_cek: bytes

    def encode(self) -> bytes:
        digest = hashlib.sha256(self.wrapped_cek).digest()
        return self.request_id.to_bytes(8, "big") + digest


@dataclass
class PendingResult:
    confirmed: asyncio.Event
    cek: bytes | None = None


class ArtificialStorage:
    def __init__(self, record: FileRecord):
        self.record = record

    async def read(self) -> FileRecord:
        return self.record


class ArtificialClient:
    def __init__(self, authorization_key: bytes, mask_key: bytes):
        self.authorization_key = authorization_key
        self.mask_key = mask_key

    async def authorize(self, operation: Operation) -> bytes:
        return hmac.new(
            self.authorization_key, operation.encode(), hashlib.sha256
        ).digest()

    async def mask(self, operation: Operation, length: int) -> bytes:
        return derive_mask(self.mask_key, operation.request_id, length)


class ArtificialHSM:
    def __init__(
        self,
        kek: bytes,
        authorization_key: bytes,
        mask_key: bytes,
    ):
        self.kek = kek
        self.authorization_key = authorization_key
        self.mask_key = mask_key
        self.pending: dict[int, PendingResult] = {}

    def _state(self, request_id: int) -> PendingResult:
        return self.pending.setdefault(request_id, PendingResult(asyncio.Event()))

    def _check_authorization(self, operation: Operation, tag: bytes) -> None:
        expected = hmac.new(
            self.authorization_key, operation.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise PermissionError("Autorisation du client invalide")

    async def _unwrap(self, operation: Operation) -> bytes:
        return aes_key_unwrap(self.kek, operation.wrapped_cek)

    async def relay_unwrap(self, operation: Operation, tag: bytes) -> bytes:
        self._check_authorization(operation, tag)
        return await self._unwrap(operation)

    async def precompute(self, operation: Operation) -> bytes:
        state = self._state(operation.request_id)
        state.cek = await self._unwrap(operation)
        await state.confirmed.wait()
        cek = state.cek
        del self.pending[operation.request_id]
        if cek is None:
            raise RuntimeError("Résultat HSM absent")
        return cek

    async def confirm(self, operation: Operation, tag: bytes) -> None:
        self._check_authorization(operation, tag)
        self._state(operation.request_id).confirmed.set()

    async def masked_unwrap(self, operation: Operation) -> bytes:
        cek = await self._unwrap(operation)
        mask = derive_mask(self.mask_key, operation.request_id, len(cek))
        return xor_bytes(cek, mask)


class ArtificialKMS:
    def __init__(
        self,
        client: ArtificialClient,
        hsm: ArtificialHSM,
        storage: ArtificialStorage,
        aad: bytes,
    ):
        self.client = client
        self.hsm = hsm
        self.storage = storage
        self.aad = aad

    async def _relay(self, operation: Operation) -> bytes:
        tag = await self.client.authorize(operation)
        return await self.hsm.relay_unwrap(operation, tag)

    async def _precompute(self, operation: Operation) -> bytes:
        async def hsm_path() -> bytes:
            return await self.hsm.precompute(operation)

        async def confirmation_path() -> None:
            tag = await self.client.authorize(operation)
            await self.hsm.confirm(operation, tag)

        cek, _ = await asyncio.gather(hsm_path(), confirmation_path())
        return cek

    async def _masked(self, operation: Operation) -> bytes:
        async def hsm_path() -> bytes:
            return await self.hsm.masked_unwrap(operation)

        async def client_path() -> bytes:
            return await self.client.mask(operation, 32)

        masked_cek, mask = await asyncio.gather(hsm_path(), client_path())
        return xor_bytes(masked_cek, mask)

    async def access_file(self, protocol: str, request_id: int) -> bytes:
        record = await self.storage.read()
        operation = Operation(request_id, record.wrapped_cek)

        if protocol == "relay":
            cek = await self._relay(operation)
        elif protocol == "precompute":
            cek = await self._precompute(operation)
        elif protocol == "masked":
            cek = await self._masked(operation)
        else:
            raise ValueError(f"Protocole inconnu : {protocol}")

        return AESGCM(cek).decrypt(record.nonce, record.ciphertext, self.aad)


def derive_mask(key: bytes, request_id: int, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        message = request_id.to_bytes(8, "big") + counter.to_bytes(4, "big")
        output.extend(hmac.new(key, message, hashlib.sha256).digest())
        counter += 1
    return bytes(output[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("Les deux opérandes doivent avoir la même longueur")
    return bytes(a ^ b for a, b in zip(left, right))


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "mean_ms": statistics.fmean(values),
        "median_ms": statistics.median(values),
    }


def make_system() -> tuple[ArtificialKMS, bytes]:
    rng = random.Random(SEED)
    plaintext = rng.randbytes(FILE_SIZE_KIB * 1024)
    cek = rng.randbytes(32)
    kek = rng.randbytes(32)
    authorization_key = rng.randbytes(32)
    mask_key = rng.randbytes(32)
    nonce = rng.randbytes(12)
    aad = b"benchmark-protocoles-v1"
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext, aad)
    record = FileRecord(ciphertext, nonce, aes_key_wrap(kek, cek))

    client = ArtificialClient(authorization_key, mask_key)
    hsm = ArtificialHSM(kek, authorization_key, mask_key)
    storage = ArtificialStorage(record)
    return ArtificialKMS(client, hsm, storage, aad), plaintext


async def run_benchmark() -> dict[str, list[float]]:
    kms, expected_plaintext = make_system()
    samples = {protocol: [] for protocol in PROTOCOLS}
    request_id = 0

    for _ in range(WARMUP):
        for protocol in PROTOCOLS:
            result = await kms.access_file(protocol, request_id)
            request_id += 1
            if result != expected_plaintext:
                raise RuntimeError(f"Fichier incorrect avec {protocol}")

    order_rng = random.Random(SEED + 1)
    for _ in range(ITERATIONS):
        order = list(PROTOCOLS)
        order_rng.shuffle(order)
        for protocol in order:
            start_ns = time.perf_counter_ns()
            result = await kms.access_file(protocol, request_id)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
            request_id += 1
            if result != expected_plaintext:
                raise RuntimeError(f"Fichier incorrect avec {protocol}")
            samples[protocol].append(elapsed_ms)

    return samples


def print_results(samples: dict[str, list[float]]) -> None:
    print(f"{'Protocole':34} {'Moyenne':>12} {'Médiane':>12}")
    for protocol in PROTOCOLS:
        stats = summarize(samples[protocol])
        print(
            f"{LABELS[protocol]:34} "
            f"{stats['mean_ms']:9.3f} ms  "
            f"{stats['median_ms']:9.3f} ms"
        )


def main() -> None:
    samples = asyncio.run(run_benchmark())
    print_results(samples)


if __name__ == "__main__":
    main()
