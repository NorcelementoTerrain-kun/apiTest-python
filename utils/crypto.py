import cryptography
from cryptography.hazmat.primitives.asymmetric import padding
import base64
def _encrypt_body(rsa_public_key: cryptography.hazmat.primitives.asymmetric, body_byte: bytes) -> str:
        """加密请求体"""
        encrypted_bytes = rsa_public_key.encrypt(
            body_byte,
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted_bytes).decode("utf-8")