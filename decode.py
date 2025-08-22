#!/usr/bin/env python3
"""
JWT Token Decoder

This script decodes JWT tokens and displays their header, payload, and signature information.
Supports both file input and command-line token input.
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

try:
    import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
    import cryptography.hazmat.primitives.hashes  # noqa: F401
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def decode_base64url(data):
    """Decode base64url encoded string."""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)

    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64url encoding: {e}")


def decode_jwt(token):
    """Decode JWT token and return header, payload, and signature."""
    try:
        # Remove any whitespace/newlines
        token = token.strip()

        # Split token into parts
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError(
                "Invalid JWT format. Expected 3 parts separated by '.'")

        header_encoded, payload_encoded, signature_encoded = parts

        # Decode header
        try:
            header_decoded = decode_base64url(header_encoded)
            header = json.loads(header_decoded.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decode header: {e}")

        # Decode payload
        try:
            payload_decoded = decode_base64url(payload_encoded)
            payload = json.loads(payload_decoded.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decode payload: {e}")

        # Signature (keep as base64url for display)
        signature = signature_encoded

        return header, payload, signature

    except Exception as e:
        raise ValueError(f"JWT decoding failed: {e}")


def decode_jwe(token, secret_key=None):
    """Attempt to decode JWE token using the provided secret key."""
    if not CRYPTO_AVAILABLE:
        raise ValueError(
            "Cryptography library not available. Install with: pip install cryptography")

    if not secret_key:
        raise ValueError("Secret key required for JWE decoding")

    try:
        # Remove any whitespace/newlines
        token = token.strip()

        # Split token into parts (JWE has 5 parts)
        parts = token.split('.')
        if len(parts) != 5:
            raise ValueError(
                "Invalid JWE format. Expected 5 parts separated by '.'")

        header_encoded, _, iv_encoded, ciphertext_encoded, tag_encoded = parts

        # Decode header
        try:
            header_decoded = decode_base64url(header_encoded)
            header = json.loads(header_decoded.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decode JWE header: {e}")

        # Check if this is a direct encryption (no key encryption)
        if header.get('alg') == 'dir':
            # Direct encryption - use the secret key directly
            if header.get('enc') == 'A256GCM':
                try:
                    # Decode IV, ciphertext, and tag
                    iv = decode_base64url(iv_encoded)
                    ciphertext = decode_base64url(ciphertext_encoded)
                    tag = decode_base64url(tag_encoded)

                    # Try different key derivation methods
                    key_attempts = []

                    # Method 1: Use secret key directly (padded/truncated to 32
                    # bytes)
                    key1 = secret_key.encode('utf-8')
                    if len(key1) < 32:
                        key1 = key1.ljust(32, b'\0')
                    elif len(key1) > 32:
                        key1 = key1[:32]
                    key_attempts.append(("Direct key (padded)", key1))

                    # Method 2: Use PBKDF2 key derivation
                    if CRYPTO_AVAILABLE:
                        try:
                            from cryptography.hazmat.primitives import hashes
                            from cryptography.hazmat.primitives.kdf.pbkdf2 import \
                                PBKDF2HMAC
                            kdf = PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=b'',  # Empty salt for Auth0 compatibility
                                iterations=1,
                            )
                            key2 = kdf.derive(secret_key.encode('utf-8'))
                            key_attempts.append(("PBKDF2 derived", key2))
                        except Exception:
                            pass

                    # Method 3: SHA256 hash of the secret
                    try:
                        import hashlib
                        key3 = hashlib.sha256(
                            secret_key.encode('utf-8')).digest()
                        key_attempts.append(("SHA256 hash", key3))
                    except Exception:
                        pass

                    # Try each key method
                    for key_name, key in key_attempts:
                        if not CRYPTO_AVAILABLE:
                            continue
                        try:
                            # Decrypt using AES-GCM
                            from cryptography.hazmat.primitives.ciphers.aead import \
                                AESGCM
                            aesgcm = AESGCM(key)
                            additional_data = header_encoded.encode('ascii')

                            # Combine ciphertext and tag for AESGCM
                            encrypted_data = ciphertext + tag

                            decrypted = aesgcm.decrypt(
                                iv, encrypted_data, additional_data)

                            # Parse the decrypted payload as JSON
                            payload = json.loads(decrypted.decode('utf-8'))

                            print(
                                f"✅ Successfully decrypted using: {key_name}")
                            return header, payload, None  # Success!

                        except Exception:
                            continue  # Try next key method

                    # If we get here, all key methods failed
                    raise ValueError(
                        "Failed to decrypt with any key derivation method")

                except Exception as e:
                    raise ValueError(f"Failed to decrypt JWE payload: {e}")
            else:
                raise ValueError(
                    f"Unsupported JWE encryption algorithm: {
                        header.get('enc')}")
        else:
            raise ValueError(
                f"Unsupported JWE key algorithm: {
                    header.get('alg')}")

    except Exception as e:
        raise ValueError(f"JWE decoding failed: {e}")


def decode_token(token, secret_keys=None):
    """Attempt to decode a token as either JWT or JWE."""
    # First try as JWT
    try:
        return decode_jwt(token), "JWT"
    except ValueError:
        pass

    # If JWT fails, try as JWE with available secret keys
    if secret_keys:
        for key_name, secret_key in secret_keys.items():
            try:
                result = decode_jwe(token, secret_key)
                return result, f"JWE (using {key_name})"
            except ValueError:
                continue

    # If both fail, raise the original JWT error for clarity
    raise ValueError("Unable to decode token as either JWT or JWE")


def format_timestamp(timestamp):
    """Convert Unix timestamp to human-readable format."""
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError):
        return str(timestamp)


def display_token_info(header, payload, signature, token_type="JWT"):
    """Display formatted token information."""
    print("=" * 60)
    print(f"{token_type} TOKEN DECODER")
    print("=" * 60)

    # Header
    print("\n📋 HEADER:")
    print("-" * 20)
    print(json.dumps(header, indent=2))

    # Payload
    print("\n📦 PAYLOAD:")
    print("-" * 20)

    # Format common JWT claims with descriptions
    formatted_payload = {}
    claim_descriptions = {
        'iss': 'Issuer',
        'sub': 'Subject',
        'aud': 'Audience',
        'exp': 'Expiration Time',
        'nbf': 'Not Before',
        'iat': 'Issued At',
        'jti': 'JWT ID',
        'name': 'Full Name',
        'nickname': 'Nickname',
        'email': 'Email',
        'picture': 'Profile Picture',
        'updated_at': 'Last Updated',
        'sid': 'Session ID',
        'nonce': 'Nonce'
    }

    for key, value in payload.items():
        description = claim_descriptions.get(key, key.title())

        # Format timestamps
        if key in ['exp', 'nbf', 'iat'] and isinstance(value, (int, float)):
            formatted_value = f"{value} ({format_timestamp(value)})"
        else:
            formatted_value = value

        formatted_payload[f"{description} ({key})"] = formatted_value

    print(json.dumps(formatted_payload, indent=2))

    # Token validity
    print("\n⏰ TOKEN VALIDITY:")
    print("-" * 20)
    current_time = datetime.now(timezone.utc).timestamp()

    if 'iat' in payload:
        iat_time = payload['iat']
        print(f"Issued: {format_timestamp(iat_time)}")

    if 'exp' in payload:
        exp_time = payload['exp']
        print(f"Expires: {format_timestamp(exp_time)}")

        if current_time > exp_time:
            print("🔴 Status: EXPIRED")
        else:
            time_left = exp_time - current_time
            hours_left = int(time_left // 3600)
            minutes_left = int((time_left % 3600) // 60)
            print(
                f"🟢 Status: VALID (expires in {hours_left}h {minutes_left}m)")

    # Signature (only for JWT)
    if signature is not None:
        print("\n🔐 SIGNATURE:")
        print("-" * 20)
        print(f"Base64URL: {signature[:50]}...")
        print(f"Length: {len(signature)} characters")
    else:
        print("\n🔐 ENCRYPTION:")
        print("-" * 20)
        print("This token was encrypted (JWE) and has been successfully decrypted")

    print("\n" + "=" * 60)


def process_json_response(file_path):
    """Process JSON file containing access_token and id_token fields."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        tokens_found = []

        # Check for access_token
        if 'access_token' in data:
            tokens_found.append(('ACCESS TOKEN', data['access_token']))

        # Check for id_token
        if 'id_token' in data:
            tokens_found.append(('ID TOKEN', data['id_token']))

        if not tokens_found:
            print("Error: No 'access_token' or 'id_token' fields found in JSON file")
            sys.exit(1)

        return tokens_found

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)


def display_token_header(token_type):
    """Display header for each token type."""
    print("\n" + "=" * 80)
    print(f"🔑 {token_type}")
    print("=" * 80)


def main():
    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(description='Decode JWT/JWE tokens')
    parser.add_argument('token', nargs='?', help='JWT/JWE token string')
    parser.add_argument(
        '-f', '--file',
        help='Read token from file (supports plain JWT or JSON with access_token/id_token fields)')

    args = parser.parse_args()

    # Get secret keys from environment
    app_secret = os.getenv('APP_SECRET_KEY')
    auth0_secret = os.getenv('AUTH0_CLIENT_SECRET')

    secret_keys = {}
    if app_secret:
        secret_keys['APP_SECRET_KEY'] = app_secret
        print(
            f"🔑 Loaded APP_SECRET_KEY from environment (length: {
                len(app_secret)})")
    if auth0_secret:
        secret_keys['AUTH0_CLIENT_SECRET'] = auth0_secret
        print(
            f"🔑 Loaded AUTH0_CLIENT_SECRET from environment (length: {
                len(auth0_secret)})")

    if not secret_keys:
        print(
            "⚠️  No secret keys found in environment - JWE decoding will not be available")

    # Get token from file or command line
    if args.file:
        # First, try to read as JSON
        try:
            with open(args.file, 'r') as f:
                content = f.read().strip()

            # Try to parse as JSON first
            try:
                json.loads(content)
                # If it's valid JSON, process it as JSON response
                tokens = process_json_response(args.file)

                for token_type, token in tokens:
                    display_token_header(token_type)
                    try:
                        (header, payload, signature), decoded_type = decode_token(
                            token, secret_keys)
                        display_token_info(
                            header, payload, signature, decoded_type)
                    except ValueError as e:
                        print(f"Error decoding {token_type}: {e}")
                        if token_type == "ACCESS TOKEN" and secret_keys:
                            print(
                                "💡 Note: This access token appears to be a JWE "
                                "(JSON Web Encryption) token.")
                            print(
                                f"   Attempted decryption with " f"{
                                    ', '.join(
                                        secret_keys.keys())} but failed.")
                            print(
                                "   The token may use a different encryption key or algorithm.")
                        elif token_type == "ACCESS TOKEN" and not secret_keys:
                            print(
                                "💡 Note: This access token appears to be a JWE "
                                "(JSON Web Encryption) token,")
                            print(
                                "   but no APP_SECRET_KEY was found in the environment "
                                "for decryption.")
                        print()
                        continue
                return

            except json.JSONDecodeError:
                # Not JSON, treat as plain JWT token
                token = content

        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

    elif args.token:
        token = args.token
    else:
        print("Error: Please provide a token string or use -f to specify a file")
        print("Usage: python decode.py <token> OR python decode.py -f <file>")
        print("       File can contain a plain JWT token or JSON with "
              "'access_token'/'id_token' fields")
        sys.exit(1)

    # Process single token (from command line or plain file)
    try:
        (header, payload, signature), decoded_type = decode_token(token, secret_keys)
        display_token_info(header, payload, signature, decoded_type)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
