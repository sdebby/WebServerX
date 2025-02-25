# 19.02.2025
# Generate an RSA asymmetric key pair

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

class KeyGen:
    def generate_rsa_key_pair():
        """Generates an RSA key pair and saves them to files."""
        print("[*] Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() 
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save keys to files
        with open("private_key.pem", "wb") as f:  # Use "wb" for binary write
            f.write(private_pem)
        with open("public_key.pem", "wb") as f:
            f.write(public_pem)
        
        return private_pem, public_pem # Return the keys as PEM strings

    def load_key_from_file(filename, is_private=False):
        """Loads a key (private or public) from a file."""
        try:
            with open(filename, "rb") as f:  # Use "rb" for binary read
                key_data = f.read()
                if is_private:
                    return serialization.load_pem_private_key(key_data, password=None, backend=default_backend()) # No password here
                else:
                    return serialization.load_pem_public_key(key_data, backend=default_backend())
        except FileNotFoundError:
            print(f"[X] Error: Key file '{filename}' not found.")
            return None
        except Exception as e: # Handle any other exceptions during file loading
            print(f"[X] Error loading key from '{filename}': {e}")
            return None

    def sign_api_request(private_key, data_to_sign): 
        """Signs data with the private key."""
        signature = private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_api_request(public_key, data_to_verify, signature): 
        """Verifies the signature with the public key."""
        decoded_signature = base64.b64decode(signature.encode('utf-8'))
        try:
            public_key.verify(
                decoded_signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False