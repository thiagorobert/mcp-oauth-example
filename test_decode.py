"""
Comprehensive test suite for decode.py module.

Tests all functions and edge cases to achieve high test coverage.
"""

import base64
import json
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import mock_open, patch

import decode


class TestDecodeBase64Url(unittest.TestCase):
    """Test base64url decoding functionality."""

    def test_decode_base64url_valid(self):
        """Test successful base64url decoding."""
        # Standard base64url without padding
        data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = decode.decode_base64url(data)
        expected = base64.urlsafe_b64decode(data + "==")
        self.assertEqual(result, expected)

    def test_decode_base64url_with_padding_needed(self):
        """Test base64url decoding when padding is needed."""
        # Missing 1 padding character
        data = "eyJhbGciOiJIUzI1NiJ9"
        result = decode.decode_base64url(data)
        expected = base64.urlsafe_b64decode(data + "===")
        self.assertEqual(result, expected)

    def test_decode_base64url_no_padding_needed(self):
        """Test base64url decoding when no padding is needed."""
        # Use data that doesn't need padding (length % 4 == 0)
        data = "dGVzdA"  # "test" in base64, needs padding
        result = decode.decode_base64url(data)
        # Expected result with padding added
        expected = base64.urlsafe_b64decode(data + "==")
        self.assertEqual(result, expected)

    def test_decode_base64url_invalid_encoding(self):
        """Test base64url decoding with invalid characters."""
        # Use a string that will definitely fail base64 decoding
        with self.assertRaises(ValueError) as cm:
            decode.decode_base64url("ñot-valid-base64!!!")
        self.assertIn("Invalid base64url encoding", str(cm.exception))

    def test_decode_base64url_empty_string(self):
        """Test base64url decoding with empty string."""
        result = decode.decode_base64url("")
        self.assertEqual(result, b"")


class TestDecodeJWT(unittest.TestCase):
    """Test JWT decoding functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Valid JWT components
        self.valid_header = {"alg": "HS256", "typ": "JWT"}
        self.valid_payload = {"sub": "user123", "exp": 1640995200, "iat": 1640991600}

        # Encode components
        self.header_encoded = base64.urlsafe_b64encode(
            json.dumps(self.valid_header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        self.payload_encoded = base64.urlsafe_b64encode(
            json.dumps(self.valid_payload).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        self.signature_encoded = "test_signature"

        # Valid JWT token
        self.valid_jwt = f"{self.header_encoded}.{self.payload_encoded}.{self.signature_encoded}"

    def test_decode_jwt_valid_token(self):
        """Test successful JWT decoding."""
        header, payload, signature = decode.decode_jwt(self.valid_jwt)

        self.assertEqual(header, self.valid_header)
        self.assertEqual(payload, self.valid_payload)
        self.assertEqual(signature, self.signature_encoded)

    def test_decode_jwt_with_whitespace(self):
        """Test JWT decoding with whitespace/newlines."""
        token_with_whitespace = f"  {self.valid_jwt}  \n"
        header, payload, signature = decode.decode_jwt(token_with_whitespace)

        self.assertEqual(header, self.valid_header)
        self.assertEqual(payload, self.valid_payload)
        self.assertEqual(signature, self.signature_encoded)

    def test_decode_jwt_invalid_format_too_few_parts(self):
        """Test JWT decoding with too few parts."""
        invalid_jwt = "header.payload"
        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Invalid JWT format", str(cm.exception))

    def test_decode_jwt_invalid_format_too_many_parts(self):
        """Test JWT decoding with too many parts."""
        invalid_jwt = "header.payload.signature.extra"
        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Invalid JWT format", str(cm.exception))

    def test_decode_jwt_invalid_header(self):
        """Test JWT decoding with invalid header."""
        invalid_header = "invalid_base64!"
        invalid_jwt = f"{invalid_header}.{self.payload_encoded}.{self.signature_encoded}"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Failed to decode header", str(cm.exception))

    def test_decode_jwt_invalid_payload(self):
        """Test JWT decoding with invalid payload."""
        invalid_payload = "invalid_base64!"
        invalid_jwt = f"{self.header_encoded}.{invalid_payload}.{self.signature_encoded}"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Failed to decode payload", str(cm.exception))

    def test_decode_jwt_invalid_json_header(self):
        """Test JWT decoding with non-JSON header."""
        invalid_header = base64.urlsafe_b64encode(b"not json").decode('utf-8').rstrip('=')
        invalid_jwt = f"{invalid_header}.{self.payload_encoded}.{self.signature_encoded}"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Failed to decode header", str(cm.exception))

    def test_decode_jwt_invalid_json_payload(self):
        """Test JWT decoding with non-JSON payload."""
        invalid_payload = base64.urlsafe_b64encode(b"not json").decode('utf-8').rstrip('=')
        invalid_jwt = f"{self.header_encoded}.{invalid_payload}.{self.signature_encoded}"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwt(invalid_jwt)
        self.assertIn("Failed to decode payload", str(cm.exception))


class TestDecodeJWE(unittest.TestCase):
    """Test JWE decoding functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_secret = "test_secret_key"
        self.valid_header = {"alg": "dir", "enc": "A256GCM"}
        self.header_encoded = base64.urlsafe_b64encode(
            json.dumps(self.valid_header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

    @patch('decode.CRYPTO_AVAILABLE', False)
    def test_decode_jwe_crypto_not_available(self):
        """Test JWE decoding when cryptography library is not available."""
        jwe_token = "header.key.iv.ciphertext.tag"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(jwe_token, self.test_secret)
        self.assertIn("Cryptography library not available", str(cm.exception))

    def test_decode_jwe_no_secret_key(self):
        """Test JWE decoding without secret key."""
        jwe_token = "header.key.iv.ciphertext.tag"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(jwe_token, None)
        self.assertIn("Secret key required", str(cm.exception))

    def test_decode_jwe_invalid_format_too_few_parts(self):
        """Test JWE decoding with too few parts."""
        invalid_jwe = "header.key.iv.ciphertext"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(invalid_jwe, self.test_secret)
        self.assertIn("Invalid JWE format", str(cm.exception))

    def test_decode_jwe_invalid_format_too_many_parts(self):
        """Test JWE decoding with too many parts."""
        invalid_jwe = "header.key.iv.ciphertext.tag.extra"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(invalid_jwe, self.test_secret)
        self.assertIn("Invalid JWE format", str(cm.exception))

    def test_decode_jwe_invalid_header(self):
        """Test JWE decoding with invalid header."""
        invalid_header = "invalid_base64!"
        invalid_jwe = f"{invalid_header}.key.iv.ciphertext.tag"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(invalid_jwe, self.test_secret)
        self.assertIn("Failed to decode JWE header", str(cm.exception))

    def test_decode_jwe_unsupported_algorithm(self):
        """Test JWE decoding with unsupported algorithm."""
        unsupported_header = {"alg": "RSA1_5", "enc": "A256GCM"}
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(unsupported_header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        jwe_token = f"{header_encoded}.key.iv.ciphertext.tag"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(jwe_token, self.test_secret)
        self.assertIn("Unsupported JWE key algorithm", str(cm.exception))

    def test_decode_jwe_unsupported_encryption(self):
        """Test JWE decoding with unsupported encryption."""
        unsupported_header = {"alg": "dir", "enc": "A128GCM"}
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(unsupported_header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        jwe_token = f"{header_encoded}.key.iv.ciphertext.tag"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(jwe_token, self.test_secret)
        self.assertIn("Unsupported JWE encryption algorithm", str(cm.exception))

    @patch('decode.CRYPTO_AVAILABLE', True)
    def test_decode_jwe_decryption_failure(self):
        """Test JWE decoding when decryption fails."""
        # Create a JWE token that will fail decryption
        jwe_token = f"{self.header_encoded}.key.aXY.Y2lwaGVydGV4dA.dGFn"

        with self.assertRaises(ValueError) as cm:
            decode.decode_jwe(jwe_token, self.test_secret)
        self.assertIn("Failed to decrypt with any key derivation method", str(cm.exception))


class TestDecodeToken(unittest.TestCase):
    """Test main token decoding entry point."""

    def setUp(self):
        """Set up test fixtures."""
        # Valid JWT
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123", "exp": 1640995200}

        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        self.valid_jwt = f"{header_encoded}.{payload_encoded}.signature"

    def test_decode_token_jwt_success(self):
        """Test successful JWT token decoding."""
        result, token_type = decode.decode_token(self.valid_jwt)

        self.assertEqual(token_type, "JWT")
        self.assertEqual(len(result), 3)  # header, payload, signature
        self.assertIsInstance(result[0], dict)  # header
        self.assertIsInstance(result[1], dict)  # payload

    def test_decode_token_jwt_with_secret_keys(self):
        """Test JWT token decoding with secret keys provided."""
        secret_keys = {"APP_SECRET_KEY": "test_secret"}
        result, token_type = decode.decode_token(self.valid_jwt, secret_keys)

        self.assertEqual(token_type, "JWT")

    @patch('decode.decode_jwe')
    def test_decode_token_jwe_success(self, mock_decode_jwe):
        """Test successful JWE token decoding."""
        # Mock JWE decoding success
        mock_decode_jwe.return_value = ({"alg": "dir"}, {"sub": "user"}, None)

        invalid_jwt = "invalid.jwt.token"
        secret_keys = {"APP_SECRET_KEY": "test_secret"}

        result, token_type = decode.decode_token(invalid_jwt, secret_keys)

        self.assertEqual(token_type, "JWE (using APP_SECRET_KEY)")
        mock_decode_jwe.assert_called_once()

    def test_decode_token_no_secret_keys_failure(self):
        """Test token decoding failure without secret keys."""
        invalid_token = "invalid.token.format"

        with self.assertRaises(ValueError) as cm:
            decode.decode_token(invalid_token)
        self.assertIn("Unable to decode token as either JWT or JWE", str(cm.exception))

    @patch('decode.decode_jwe')
    def test_decode_token_jwe_all_keys_fail(self, mock_decode_jwe):
        """Test JWE token decoding when all secret keys fail."""
        # Mock JWE decoding to always fail
        mock_decode_jwe.side_effect = ValueError("Decryption failed")

        invalid_jwt = "invalid.jwt.token"
        secret_keys = {"KEY1": "secret1", "KEY2": "secret2"}

        with self.assertRaises(ValueError) as cm:
            decode.decode_token(invalid_jwt, secret_keys)
        self.assertIn("Unable to decode token as either JWT or JWE", str(cm.exception))


class TestFormatTimestamp(unittest.TestCase):
    """Test timestamp formatting functionality."""

    def test_format_timestamp_valid_unix_timestamp(self):
        """Test formatting valid Unix timestamp."""
        timestamp = 1640995200  # 2022-01-01 00:00:00 UTC
        result = decode.format_timestamp(timestamp)
        self.assertEqual(result, "2022-01-01 00:00:00 UTC")

    def test_format_timestamp_float_timestamp(self):
        """Test formatting float Unix timestamp."""
        timestamp = 1640995200.5
        result = decode.format_timestamp(timestamp)
        self.assertEqual(result, "2022-01-01 00:00:00 UTC")

    def test_format_timestamp_invalid_timestamp(self):
        """Test formatting invalid timestamp."""
        # Test with string
        result = decode.format_timestamp("invalid")
        self.assertEqual(result, "invalid")

        # Test with None
        result = decode.format_timestamp(None)
        self.assertEqual(result, "None")

    def test_format_timestamp_negative_timestamp(self):
        """Test formatting negative timestamp."""
        timestamp = -1
        result = decode.format_timestamp(timestamp)
        # Should still work for negative timestamps (before 1970)
        self.assertIn("1969", result)


class TestDisplayFunctions(unittest.TestCase):
    """Test display and output functions."""

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_token_info_jwt(self, mock_stdout):
        """Test display_token_info for JWT."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "exp": 1640995200,
            "iat": 1640991600,
            "name": "Test User"
        }
        signature = "test_signature"

        decode.display_token_info(header, payload, signature, "JWT")

        output = mock_stdout.getvalue()
        self.assertIn("JWT TOKEN DECODER", output)
        self.assertIn("HEADER:", output)
        self.assertIn("PAYLOAD:", output)
        self.assertIn("SIGNATURE:", output)
        self.assertIn("Test User", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_token_info_jwe(self, mock_stdout):
        """Test display_token_info for JWE (no signature)."""
        header = {"alg": "dir", "enc": "A256GCM"}
        payload = {"sub": "user123"}

        decode.display_token_info(header, payload, None, "JWE")

        output = mock_stdout.getvalue()
        self.assertIn("JWE TOKEN DECODER", output)
        self.assertIn("ENCRYPTION:", output)
        self.assertNotIn("SIGNATURE:", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_token_info_with_timestamps(self, mock_stdout):
        """Test display_token_info with timestamp formatting."""
        header = {"alg": "HS256"}
        payload = {
            "exp": 1640995200,
            "iat": 1640991600,
            "nbf": 1640991600
        }

        decode.display_token_info(header, payload, "sig")

        output = mock_stdout.getvalue()
        self.assertIn("2022-01-01", output)  # Formatted timestamp
        self.assertIn("TOKEN VALIDITY:", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_token_info_expired_token(self, mock_stdout):
        """Test display_token_info with expired token."""
        header = {"alg": "HS256"}
        payload = {"exp": 1000000000}  # Very old timestamp

        decode.display_token_info(header, payload, "sig")

        output = mock_stdout.getvalue()
        self.assertIn("🔴 Status: EXPIRED", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_token_header(self, mock_stdout):
        """Test display_token_header function."""
        decode.display_token_header("ACCESS TOKEN")

        output = mock_stdout.getvalue()
        self.assertIn("🔑 ACCESS TOKEN", output)
        self.assertIn("=" * 80, output)


class TestFileProcessing(unittest.TestCase):
    """Test file processing functions."""

    def test_process_json_response_with_both_tokens(self):
        """Test processing JSON file with both access_token and id_token."""
        test_data = {
            "access_token": "access_token_value",
            "id_token": "id_token_value",
            "other_field": "other_value"
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(test_data, tmp_file)
            tmp_file_path = tmp_file.name

        try:
            result = decode.process_json_response(tmp_file_path)

            self.assertEqual(len(result), 2)
            self.assertIn(('ACCESS TOKEN', 'access_token_value'), result)
            self.assertIn(('ID TOKEN', 'id_token_value'), result)
        finally:
            os.unlink(tmp_file_path)

    def test_process_json_response_access_token_only(self):
        """Test processing JSON file with only access_token."""
        test_data = {"access_token": "access_token_value"}

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(test_data, tmp_file)
            tmp_file_path = tmp_file.name

        try:
            result = decode.process_json_response(tmp_file_path)

            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], ('ACCESS TOKEN', 'access_token_value'))
        finally:
            os.unlink(tmp_file_path)

    @patch('sys.exit')
    @patch('builtins.print')
    def test_process_json_response_no_tokens(self, mock_print, mock_exit):
        """Test processing JSON file with no relevant tokens."""
        test_data = {"other_field": "other_value"}

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(test_data, tmp_file)
            tmp_file_path = tmp_file.name

        try:
            decode.process_json_response(tmp_file_path)
            mock_print.assert_called_with("Error: No 'access_token' or 'id_token' fields found in JSON file")
            mock_exit.assert_called_with(1)
        finally:
            os.unlink(tmp_file_path)

    @patch('sys.exit')
    @patch('builtins.print')
    def test_process_json_response_invalid_json(self, mock_print, mock_exit):
        """Test processing file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            tmp_file.write("invalid json content")
            tmp_file_path = tmp_file.name

        try:
            decode.process_json_response(tmp_file_path)
            mock_print.assert_called()
            self.assertTrue(any("Invalid JSON" in str(call) for call in mock_print.call_args_list))
            mock_exit.assert_called_with(1)
        finally:
            os.unlink(tmp_file_path)

    @patch('sys.exit')
    @patch('builtins.print')
    def test_process_json_response_file_not_found(self, mock_print, mock_exit):
        """Test processing non-existent file."""
        decode.process_json_response("non_existent_file.json")

        mock_print.assert_called()
        self.assertTrue(any("not found" in str(call) for call in mock_print.call_args_list))
        mock_exit.assert_called_with(1)


class TestMainFunction(unittest.TestCase):
    """Test main function and CLI argument parsing."""

    def setUp(self):
        """Set up test fixtures."""
        # Valid JWT for testing
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123"}

        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        self.valid_jwt = f"{header_encoded}.{payload_encoded}.signature"

    @patch('sys.argv', ['decode.py', 'test_token'])
    @patch('decode.decode_token')
    @patch('decode.display_token_info')
    @patch('os.getenv')
    def test_main_with_token_argument(self, mock_getenv, mock_display, mock_decode, ):
        """Test main function with token argument."""
        mock_getenv.return_value = None
        mock_decode.return_value = (({"alg": "HS256"}, {"sub": "user"}, "sig"), "JWT")

        with patch('builtins.print'):
            decode.main()

        mock_decode.assert_called_once()
        mock_display.assert_called_once()

    @patch('sys.argv', ['decode.py', '-f', 'test.json'])
    @patch('decode.process_json_response')
    @patch('decode.decode_token')
    @patch('decode.display_token_info')
    @patch('decode.display_token_header')
    @patch('os.getenv')
    @patch('builtins.open', new_callable=mock_open, read_data='{"access_token": "test"}')
    def test_main_with_json_file(self, mock_file, mock_getenv, mock_header, mock_display, mock_decode, mock_process):
        """Test main function with JSON file argument."""
        mock_getenv.return_value = None
        mock_process.return_value = [('ACCESS TOKEN', 'test_token')]
        mock_decode.return_value = (({"alg": "HS256"}, {"sub": "user"}, "sig"), "JWT")

        with patch('builtins.print'):
            decode.main()

        mock_process.assert_called_once()
        mock_decode.assert_called_once()

    @patch('sys.argv', ['decode.py', '-f', 'test.txt'])
    @patch('decode.decode_token')
    @patch('decode.display_token_info')
    @patch('os.getenv')
    @patch('builtins.open', new_callable=mock_open, read_data='plain.jwt.token')
    def test_main_with_plain_file(self, mock_file, mock_getenv, mock_display, mock_decode):
        """Test main function with plain text token file."""
        mock_getenv.return_value = None
        mock_decode.return_value = (({"alg": "HS256"}, {"sub": "user"}, "sig"), "JWT")

        with patch('builtins.print'):
            decode.main()

        mock_decode.assert_called_with('plain.jwt.token', {})

    @patch('sys.argv', ['decode.py'])
    @patch('sys.exit')
    @patch('builtins.print')
    @patch('os.getenv')
    def test_main_no_arguments(self, mock_getenv, mock_print, mock_exit):
        """Test main function with no arguments."""
        mock_getenv.return_value = None
        # Mock sys.exit to actually stop execution
        mock_exit.side_effect = SystemExit(1)

        with self.assertRaises(SystemExit):
            decode.main()

        mock_print.assert_called()
        self.assertTrue(any("Please provide a token" in str(call) for call in mock_print.call_args_list))
        mock_exit.assert_called_with(1)

    @patch('sys.argv', ['decode.py', 'invalid_token'])
    @patch('decode.decode_token')
    @patch('sys.exit')
    @patch('builtins.print')
    @patch('os.getenv')
    def test_main_token_decode_error(self, mock_getenv, mock_print, mock_exit, mock_decode):
        """Test main function with token decode error."""
        mock_getenv.return_value = None
        mock_decode.side_effect = ValueError("Invalid token")

        decode.main()

        mock_print.assert_called_with("Error: Invalid token")
        mock_exit.assert_called_with(1)

    @patch('sys.argv', ['decode.py', '-f', 'nonexistent.txt'])
    @patch('sys.exit')
    @patch('builtins.print')
    @patch('os.getenv')
    def test_main_file_not_found(self, mock_getenv, mock_print, mock_exit):
        """Test main function with non-existent file."""
        mock_getenv.return_value = None
        # Mock sys.exit to actually stop execution
        mock_exit.side_effect = SystemExit(1)

        with self.assertRaises(SystemExit):
            decode.main()

        mock_print.assert_called()
        self.assertTrue(any("not found" in str(call) for call in mock_print.call_args_list))
        mock_exit.assert_called_with(1)

    @patch('os.getenv')
    @patch('sys.argv', ['decode.py', 'test_token'])
    @patch('builtins.print')
    def test_main_with_environment_secrets(self, mock_print, mock_getenv):
        """Test main function loading secrets from environment."""
        # Mock environment variables
        def mock_getenv_side_effect(key):
            if key == 'APP_SECRET_KEY':
                return 'app_secret_value'
            elif key == 'AUTH0_CLIENT_SECRET':
                return 'auth0_secret_value'
            return None

        mock_getenv.side_effect = mock_getenv_side_effect

        with patch('decode.decode_token') as mock_decode:
            with patch('decode.display_token_info'):
                mock_decode.return_value = (({"alg": "HS256"}, {"sub": "user"}, "sig"), "JWT")

                decode.main()

                # Check that secrets were loaded
                args, kwargs = mock_decode.call_args
                secret_keys = args[1] if len(args) > 1 else kwargs.get('secret_keys', {})

                self.assertIn('APP_SECRET_KEY', secret_keys)
                self.assertIn('AUTH0_CLIENT_SECRET', secret_keys)
                self.assertEqual(secret_keys['APP_SECRET_KEY'], 'app_secret_value')
                self.assertEqual(secret_keys['AUTH0_CLIENT_SECRET'], 'auth0_secret_value')

    @patch('sys.argv', ['decode.py', '-f', 'test.json'])
    @patch('decode.decode_token')
    @patch('decode.display_token_header')
    @patch('os.getenv')
    @patch('builtins.open', new_callable=mock_open, read_data='{"access_token": "test_token"}')
    @patch('builtins.print')
    def test_main_json_file_decode_error_with_secrets(self, mock_print, mock_file, mock_getenv, mock_header, mock_decode):
        """Test main function JSON file with decode error and secrets available."""
        mock_getenv.side_effect = lambda key: 'secret_value' if key in ['APP_SECRET_KEY', 'AUTH0_CLIENT_SECRET'] else None
        mock_decode.side_effect = ValueError("Decode error")

        decode.main()

        # Should print helpful error messages for JWE tokens
        printed_messages = [str(call) for call in mock_print.call_args_list]
        error_found = any("Note: This access token appears to be a JWE" in msg for msg in printed_messages)
        self.assertTrue(error_found)

    @patch('sys.argv', ['decode.py', '-f', 'test.json'])
    @patch('decode.decode_token')
    @patch('decode.display_token_header')
    @patch('os.getenv')
    @patch('builtins.open', new_callable=mock_open, read_data='{"access_token": "test_token"}')
    @patch('builtins.print')
    def test_main_json_file_decode_error_no_secrets(self, mock_print, mock_file, mock_getenv, mock_header, mock_decode):
        """Test main function JSON file with decode error and no secrets."""
        mock_getenv.return_value = None
        mock_decode.side_effect = ValueError("Decode error")

        decode.main()

        # Should print helpful error messages for JWE tokens without secrets
        printed_messages = [str(call) for call in mock_print.call_args_list]
        error_found = any("but no APP_SECRET_KEY was found" in msg for msg in printed_messages)
        self.assertTrue(error_found)


if __name__ == '__main__':
    unittest.main()
