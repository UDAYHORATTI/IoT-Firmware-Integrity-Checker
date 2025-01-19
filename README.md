# IoT-Firmware-Integrity-Checker
This project verifies the integrity of IoT firmware files to ensure they haven’t been tampered with or corrupted, using cryptographic hashing and signature verification.
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization

def calculate_hash(file_path, hash_algorithm="sha256"):
    """
    Calculate the hash of the firmware file.
    """
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None

def verify_signature(file_path, signature_path, public_key_path):
    """
    Verify the digital signature of the firmware using the public key.
    """
    try:
        # Load the firmware
        with open(file_path, "rb") as firmware_file:
            firmware_data = firmware_file.read()

        # Load the signature
        with open(signature_path, "rb") as signature_file:
            signature = signature_file.read()

        # Load the public key
        with open(public_key_path, "rb") as pub_key_file:
            public_key_data = pub_key_file.read()
            public_key = load_pem_public_key(public_key_data)

        # Verify the signature
        public_key.verify(
            signature,
            firmware_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verification: PASSED")
        return True
    except Exception as e:
        print(f"Signature verification: FAILED - {e}")
        return False

def main():
    # Paths
    firmware_path = input("Enter the firmware file path: ")
    signature_path = input("Enter the signature file path: ")
    public_key_path = input("Enter the public key file path: ")
    known_hash = input("Enter the known secure hash (or leave blank to skip): ")

    # Step 1: Hash verification
    print("\n=== Step 1: Firmware Hash Verification ===")
    firmware_hash = calculate_hash(firmware_path)
    if firmware_hash:
        print(f"Calculated Hash: {firmware_hash}")
        if known_hash:
            if firmware_hash == known_hash:
                print("Hash verification: PASSED")
            else:
                print("Hash verification: FAILED (Hashes do not match)")
        else:
            print("No known hash provided. Skipping hash comparison.")

    # Step 2: Signature verification
    print("\n=== Step 2: Firmware Signature Verification ===")
    verify_signature(firmware_path, signature_path, public_key_path)

if __name__ == "__main__":
    main()
