import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self, master_password: str, salt: bytes, iterations: int = 200_000):
        if not isinstance(salt, bytes):
            raise TypeError('salt must be bytes')
        self.iterations = iterations
        self.salt = salt
        self.master_password = master_password.encode('utf-8')
        self._key = self._derive_key()

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        raw = kdf.derive(self.master_password)
        return base64.urlsafe_b64encode(raw)

    def fernet(self) -> Fernet:
        return Fernet(self._key)

    def encrypt(self, plaintext: str) -> bytes:
        return self.fernet().encrypt(plaintext.encode('utf-8'))

    def decrypt(self, token: bytes) -> str:
        try:
            pt = self.fernet().decrypt(token)
            return pt.decode('utf-8')
        except InvalidToken as e:
            raise ValueError('Invalid decryption token - wrong master password or corrupted data') from e

    def verifier(self) -> str:
        return hashlib.sha256(self._key).hexdigest()
