#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
                    CRYPTO_UTILS — гибридное RSA+AES шифрование отчёта
================================================================================

Схема (стандартный "hybrid encryption", то же самое по идее, что делает
age/PGP при шифровании "на чужой публичный ключ"):

    1. Для каждого отчёта генерируется СЛУЧАЙНЫЙ одноразовый AES-ключ.
    2. Текст отчёта шифруется этим AES-ключом (быстро, т.к. отчёт большой).
    3. Сам AES-ключ шифруется публичным RSA-ключом владельца (PUBLIC_KEY_PEM).
    4. В файл отчёта попадает: зашифрованный AES-ключ + зашифрованный текст.

Расшифровать способен только тот, у кого есть приватный RSA-ключ — то есть
только владелец (см. keygen.py и decryptor.py). Игрок, запустивший программу,
не может ни прочитать чужой отчёт, ни подделать свой так, чтобы подделка
прошла проверку: у него физически нет приватного ключа, которым можно было
бы зашифровать "нужный" AES-ключ так, чтобы владелец получил при расшифровке
что-то осмысленное.

ВАЖНО: PUBLIC_KEY_PEM ниже — это ПУБЛИЧНЫЙ ключ. Его можно свободно
встраивать в код/.exe, который получают игроки. Приватный ключ
(private_key.pem) сюда никогда не попадает.
================================================================================
"""

import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================================================
# ПУБЛИЧНЫЙ КЛЮЧ ВЛАДЕЛЬЦА (безопасно хранить прямо в коде/.exe)
#
# Сгенерирован примером через keygen.py. ПЕРЕД реальным использованием
# запусти keygen.py у себя и вставь СВОЙ публичный ключ сюда — тогда
# расшифровать отчёты сможешь только ты своим private_key.pem.
# ============================================================================
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcfMJukconxD5lzpY9EI
Mk3kbSmv12Vu28E9gFlMuxrbJ8MZ1GIw6haZguOA5LehoHkU1Twu0Gy5Dn5I3i6J
mZncRIIVIOGUhM6iwxWelVh8Z8Kh1CHzLbExny1ByIm4M5FChgEZH/TAHKePh+gL
6Bj40Zg3TRzyDtKzWxEQv8BQEByauDV2zTRKpUnly3S6/06SqyWy+S5MEXPyetjK
6iQMpMenCGNonIthEZqIMX6E9tiiq+SwAxMiZo3FfjVIVZA1sH8zh/6cY29aME/u
lh91yvYC7CSo/4ME4ySSwsXdponoXwteTZjRvWD428pEYD0vDYy+Mj1JRL7HfWRw
oQIDAQAB
-----END PUBLIC KEY-----
"""

MAGIC = b"RPCC2"  # маркер формата файла отчёта


def _load_public_key():
    return serialization.load_pem_public_key(PUBLIC_KEY_PEM)


def encrypt_report(plaintext: str) -> bytes:
    """
    Шифрует текст отчёта гибридной RSA+AES-схемой.

    Формат итогового файла:
        MAGIC (5 байт) | len(enc_aes_key) (2 байта, big-endian) | enc_aes_key
        | nonce (12 байт) | ciphertext (включает AES-GCM тег)

    Args:
        plaintext: текст отчёта

    Returns:
        bytes: готовый к сохранению зашифрованный блок
    """
    public_key = _load_public_key()

    aes_key = os.urandom(32)   # AES-256
    nonce = os.urandom(12)     # для AES-GCM

    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    ciphertext += encryptor.tag  # сохраняем тег аутентификации следом

    enc_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    out = bytearray()
    out += MAGIC
    out += struct.pack(">H", len(enc_aes_key))
    out += enc_aes_key
    out += nonce
    out += ciphertext
    return bytes(out)


def decrypt_report(data: bytes, private_key_pem: bytes) -> str:
    """
    Расшифровывает отчёт приватным ключом владельца.
    Используется только в decryptor.py на стороне владельца, НЕ в программе
    для игроков.

    Args:
        data: содержимое .enc файла
        private_key_pem: содержимое private_key.pem

    Returns:
        str: текст отчёта

    Raises:
        ValueError: если формат файла неверен или данные повреждены/подделаны
    """
    if data[:5] != MAGIC:
        raise ValueError("Неверный формат файла отчёта (нет магического маркера).")

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    pos = 5
    key_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    enc_aes_key = data[pos:pos + key_len]
    pos += key_len
    nonce = data[pos:pos + 12]
    pos += 12
    ciphertext_and_tag = data[pos:]
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]

    aes_key = private_key.decrypt(
        enc_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")
