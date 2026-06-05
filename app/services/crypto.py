from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization


class PayloadDecryptError(ValueError):
    """Raised when the hybrid encrypted payload cannot be decoded or authenticated."""


def generate_rsa_key_pair() -> tuple[str, str]:
    """生成 RSA-2048 密钥对。

    私钥仅写入服务端 session；公钥以 PEM 格式下发给浏览器，用于加密浏览器
    临时生成的 AES-256 会话密钥。
    """

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def decrypt_hybrid_payload(payload: str | dict[str, Any], rsa_private_key_pem: str) -> dict[str, Any]:
    """解密 RSA + AES 混合加密 payload。

    前端 envelope 格式：
    {
        "encrypted_key": "base64(RSA-OAEP-SHA256(AES_Session_Key))",
        "encrypted_payload": {
            "iv": "base64(12 bytes nonce)",
            "ciphertext": "base64(AES-GCM(ciphertext || auth_tag))"
        }
    }

    解密步骤：
    1. 用服务端 RSA 私钥解开 AES_Session_Key。
    2. 用 AES-GCM-256 解密轨迹明文。
    3. GCM 认证失败、RSA 私钥不匹配、base64 格式错误都会被统一转为
       PayloadDecryptError，API 层安全返回失败。
    """

    try:
        envelope = json.loads(payload) if isinstance(payload, str) else payload
        if not isinstance(envelope, dict):
            raise TypeError("payload envelope must be an object")

        encrypted_key = base64.b64decode(str(envelope["encrypted_key"]), validate=True)
        encrypted_payload = envelope["encrypted_payload"]
        if not isinstance(encrypted_payload, dict):
            raise TypeError("encrypted_payload must be an object")

        iv = base64.b64decode(str(encrypted_payload["iv"]), validate=True)
        ciphertext = base64.b64decode(str(encrypted_payload["ciphertext"]), validate=True)
        if len(iv) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")

        private_key = serialization.load_pem_private_key(
            rsa_private_key_pem.encode("ascii"),
            password=None,
        )
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if len(aes_key) != 32:
            raise ValueError("AES-GCM-256 key must be 32 bytes")

        plaintext = AESGCM(aes_key).decrypt(iv, ciphertext, associated_data=None)
        decoded = json.loads(plaintext.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise TypeError("plaintext payload must be an object")
        return decoded
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, InvalidTag) as exc:
        raise PayloadDecryptError("hybrid payload decrypt/authentication failed") from exc

