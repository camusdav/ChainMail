import os
from cryptography.fernet import Fernet

class QuarantineCrypto:
    def __init__(self, key_file="quarantine.key"):
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self):
        """Carga la clave de cifrado existente o genera una nueva si no existe."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def encrypt(self, data: str) -> bytes:
        """Convierte el texto plano a bytes y lo encripta."""
        return self.cipher.encrypt(data.encode('utf-8'))

    def decrypt(self, encrypted_data: bytes) -> str:
        """Desencripta los bytes y los devuelve como texto plano."""
        return self.cipher.decrypt(encrypted_data).decode('utf-8')