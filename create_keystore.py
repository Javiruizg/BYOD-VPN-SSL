from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
import secrets
import string

# Ajusta las rutas a tus archivos .crt y .key
CERT_PATH = os.path.join("server.crt")
KEY_PATH = os.path.join("server.key")
KEYSTORE_PATH = os.path.join("keystore.p12")

# Contraseña con la que quieres cifrar el keystore
KEYSTORE_PASSWORD = b"contrasena_de_prueba"

def create_p12_keystore():
    # 1. Leer el certificado y la clave privada desde los archivos .crt y .key
    with open(CERT_PATH, "rb") as cert_file:
        cert_data = cert_file.read()

    with open(KEY_PATH, "rb") as key_file:
        key_data = key_file.read()

    # 2. Cargar el certificado y la clave privada
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

    # 3. Si tuvieras CA intermedias, podrías cargarlas y pasarlas en 'cas'
    additional_certs = None

    # 4. Crear el contenido PKCS#12
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"server", 
        key=private_key,
        cert=certificate,
        cas=additional_certs,
        encryption_algorithm=BestAvailableEncryption(KEYSTORE_PASSWORD)
    )

    # 5. Guardar el PKCS#12 en un archivo .p12
    with open(KEYSTORE_PATH, "wb") as p12_file:
        p12_file.write(p12_data)

    print(f"Archivo {KEYSTORE_PATH} creado exitosamente con contraseña: {KEYSTORE_PASSWORD.decode()}")

if __name__ == "__main__":
    create_p12_keystore()
