from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_key(password: str, salt: bytes) -> bytes:
    # Derivar una clave utilizando PBKDF2 HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_message(message: str, password: str) -> str:
    # Generar una salt y una clave derivada de la contraseña
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # Inicializar el cifrador AES en modo CBC con un IV aleatorio
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Añadir padding al mensaje
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Cifrar el mensaje
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # Codificar el mensaje cifrado, IV y salt en base64 para su almacenamiento/transmisión
    encoded_message = urlsafe_b64encode(salt + iv + encrypted_message).decode()
    return encoded_message

def decrypt_message(encoded_message: str, password: str) -> str:
    # Decodificar el mensaje cifrado en base64
    encrypted_data = urlsafe_b64decode(encoded_message.encode())

    # Extraer la salt, IV y el mensaje cifrado
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]

    # Generar la clave derivada de la contraseña y la salt
    key = generate_key(password, salt)

    # Inicializar el descifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar el mensaje y eliminar el padding
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

# Ejemplo de uso
password = "mi_contraseña_secreta"
mensaje_original = "Hola, este es un mensaje secreto."

# Cifrar el mensaje
mensaje_cifrado = encrypt_message(mensaje_original, password)
print(f"Mensaje cifrado: {mensaje_cifrado}")

# Descifrar el mensaje
mensaje_descifrado = decrypt_message(mensaje_cifrado, password)
print(f"Mensaje descifrado: {mensaje_descifrado}")
