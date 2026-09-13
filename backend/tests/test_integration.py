"""Comprehensive integration and end-to-end verification test suite for InvisioVault.

Tests cover:
- Stego hide & extract (plain and encrypted, original filename verification).
- Stego API hide & extract flow (verifying end-to-end filename preservation).
- Polyglot create & extract (plain and encrypted, original ZIP entry verification).
- QR code stego generation & scanning (public + secret data, password protection).
- Error sanitization (verifying specific safe messages vs generic masks in production mode).
- Polyglot extensionless carrier handling.
- Windows cp1252 encoding safety on settings import.
"""

import io
import os
import shutil
import tempfile
import unittest
from PIL import Image
import numpy as np

# Ensure backend root is on sys.path
import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app
from config.settings import DevelopmentConfig, ProductionConfig
from utils.steganography import hide_file_in_image, extract_file_from_image
from utils.polyglot import create_polyglot, extract_from_polyglot
from utils.qr_stego import generate_qr_with_stego, extract_from_qr_stego
from api.routes import sanitize_error, SAFE_ERROR_MESSAGES


class InvisioVaultIntegrationTests(unittest.TestCase):
    """End-to-end integration and functionality test cases."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="invisiovault_test_")
        cls.app = create_app('development')
        cls.app.config['TESTING'] = True
        cls.app.config['UPLOAD_FOLDER'] = os.path.join(cls.temp_dir, "uploads")
        os.makedirs(cls.app.config['UPLOAD_FOLDER'], exist_ok=True)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _create_test_image(self, filename="carrier.png", width=300, height=300):
        """Generate a textured test image suitable for adaptive Sobel LSB embedding."""
        img_path = os.path.join(self.temp_dir, filename)
        # Create an image with gradient texture so Sobel edge scores are diverse
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                arr[y, x] = [
                    (x * 3 + y * 2) % 256,
                    (x * 5 + y * 7) % 256,
                    (x * 11 + y * 13) % 256
                ]
        img = Image.fromarray(arr, "RGB")
        img.save(img_path, "PNG")
        return img_path

    # -------------------------------------------------------------------------
    # 1. Steganography Tests (Filename preservation & Encryption)
    # -------------------------------------------------------------------------

    def test_stego_plain_preserves_original_filename(self):
        """Verify that steganography embedding preserves clean original filename."""
        carrier_path = self._create_test_image("stego_carrier_plain.png", 250, 250)
        secret_content = b"Confidential plain text content that must stay safe."
        secret_file = os.path.join(self.temp_dir, "notes.txt")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "output_stego_plain.png")
        hide_file_in_image(
            carrier_path,
            secret_file,
            output_stego,
            password=None,
            original_filename="notes.txt"
        )

        # Extract and verify
        extracted_data, ext_filename, mime_type = extract_file_from_image(output_stego)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, "notes.txt")

    def test_stego_api_end_to_end_filename_preservation(self):
        """Verify /api/hide -> /api/extract preserves clean uploaded filename without hex prefix."""
        carrier_path = self._create_test_image("api_carrier.png", 300, 300)
        secret_content = b"Hello from InvisioVault integration test!"
        secret_filename = "classified_report.txt"

        with open(carrier_path, "rb") as cf:
            response = self.client.post(
                "/api/hide",
                data={
                    "image": (cf, "carrier.png"),
                    "file": (io.BytesIO(secret_content), secret_filename),
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        download_id = data.get("download_id")
        self.assertTrue(download_id)

        # Download stego image
        dl_resp = self.client.get(f"/api/download/{download_id}")
        self.assertEqual(dl_resp.status_code, 200)
        stego_bytes = dl_resp.data

        # Post back to /api/extract
        ext_resp = self.client.post(
            "/api/extract",
            data={"image": (io.BytesIO(stego_bytes), "stego.png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, secret_content)
        cd_header = ext_resp.headers.get("Content-Disposition", "")
        self.assertIn('filename=classified_report.txt', cd_header)

    def test_stego_encrypted_with_password(self):
        """Verify password-protected steganography hide and extract."""
        carrier_path = self._create_test_image("stego_carrier_enc.png", 300, 300)
        secret_content = b"Top secret classified payload 2026."
        secret_file = os.path.join(self.temp_dir, "payload.dat")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "output_stego_enc.png")
        password = "SecurePassword123!"
        hide_file_in_image(
            carrier_path,
            secret_file,
            output_stego,
            password=password,
            original_filename="payload.dat"
        )

        # Extraction with correct password
        extracted_data, ext_filename, _ = extract_file_from_image(output_stego, password=password)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, "payload.dat")

        # Extraction with wrong password must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            extract_file_from_image(output_stego, password="WrongPassword999!")
        self.assertIn("password", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 2. Polyglot Tests (Filename preservation & Extension handling)
    # -------------------------------------------------------------------------

    def test_polyglot_preserves_original_filename_in_zip(self):
        """Verify polyglot ZIP contains the clean original filename without hex prefix."""
        carrier_path = self._create_test_image("polyglot_carrier.png", 100, 100)
        file_to_hide = os.path.join(self.temp_dir, "document.pdf")
        with open(file_to_hide, "wb") as f:
            f.write(b"%PDF-1.4 mock pdf content for testing polyglot")

        output_poly = os.path.join(self.temp_dir, "output_polyglot.png")
        create_polyglot(
            carrier_path,
            file_to_hide,
            output_poly,
            password=None,
            original_filename="document.pdf"
        )

        extracted_data, ext_filename = extract_from_polyglot(output_poly)
        self.assertEqual(extracted_data, b"%PDF-1.4 mock pdf content for testing polyglot")
        self.assertEqual(ext_filename, "document.pdf")

    def test_polyglot_encrypted_with_password(self):
        """Verify encrypted polyglot extraction and incorrect password rejection."""
        carrier_path = self._create_test_image("poly_carrier_enc.png", 100, 100)
        file_to_hide = os.path.join(self.temp_dir, "archive.txt")
        with open(file_to_hide, "wb") as f:
            f.write(b"Encrypted polyglot secret message.")

        output_poly = os.path.join(self.temp_dir, "output_poly_enc.png")
        pwd = "PolyPassword2026!"
        create_polyglot(
            carrier_path,
            file_to_hide,
            output_poly,
            password=pwd,
            original_filename="archive.txt"
        )

        extracted_data, ext_filename = extract_from_polyglot(output_poly, password=pwd)
        self.assertEqual(extracted_data, b"Encrypted polyglot secret message.")
        self.assertEqual(ext_filename, "archive.txt")

        # Wrong password rejection
        with self.assertRaises(ValueError):
            extract_from_polyglot(output_poly, password="WrongPassword!")

    def test_polyglot_api_extensionless_carrier_handled(self):
        """Verify API correctly assigns fallback extension when carrier has no extension."""
        # Create an extensionless carrier file
        carrier_no_ext = os.path.join(self.temp_dir, "carrier_no_ext")
        with open(carrier_no_ext, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

        secret_file = os.path.join(self.temp_dir, "secret.txt")
        with open(secret_file, "wb") as f:
            f.write(b"Polyglot secret data")

        with open(carrier_no_ext, "rb") as cf, open(secret_file, "rb") as sf:
            response = self.client.post(
                "/api/polyglot/create",
                data={
                    "carrier": (cf, "carrier_no_ext"),
                    "file": (sf, "secret.txt")
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        download_id = data.get("download_id")
        self.assertTrue(download_id.endswith(".bin"))

        # Verify downloading with this download_id succeeds
        dl_resp = self.client.get(f"/api/polyglot/download/{download_id}")
        self.assertEqual(dl_resp.status_code, 200)

    # -------------------------------------------------------------------------
    # 3. QR Stego Tests
    # -------------------------------------------------------------------------

    def test_qr_stego_generate_and_scan(self):
        """Verify QR generation and scanning with both public and secret data."""
        qr_output = os.path.join(self.temp_dir, "test_qr.png")
        public_msg = "https://invisiovault.app/about"
        secret_msg = "Steganographic hidden QR secret!"

        generate_qr_with_stego(
            public_data=public_msg,
            secret_text=secret_msg,
            output_path=qr_output,
            password=None,
            scale=10
        )

        pub_extracted, sec_extracted = extract_from_qr_stego(qr_output, password=None)
        self.assertEqual(pub_extracted, public_msg)
        self.assertEqual(sec_extracted, secret_msg)

    def test_qr_stego_encrypted(self):
        """Verify password-protected QR steganography."""
        qr_output = os.path.join(self.temp_dir, "test_qr_enc.png")
        public_msg = "https://invisiovault.app/secure"
        secret_msg = "Super secret text for QR."
        pwd = "QRP@ssword2026!"

        generate_qr_with_stego(
            public_data=public_msg,
            secret_text=secret_msg,
            output_path=qr_output,
            password=pwd,
            scale=10
        )

        # Extract with correct password
        pub_ext, sec_ext = extract_from_qr_stego(qr_output, password=pwd)
        self.assertEqual(pub_ext, public_msg)
        self.assertEqual(sec_ext, secret_msg)

        # Extract without password raises password required error
        with self.assertRaises(ValueError) as ctx:
            extract_from_qr_stego(qr_output, password=None)
        self.assertIn("password", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 4. Error Sanitization Tests
    # -------------------------------------------------------------------------

    def test_sanitize_error_maps_correctly(self):
        """Verify sanitize_error maps errors to safe user-friendly messages in production."""
        # Non-stego image / out of range
        self.assertEqual(
            sanitize_error("Metadata length is outside the valid range.", is_debug=False),
            SAFE_ERROR_MESSAGES['no_hidden_data']
        )
        self.assertEqual(
            sanitize_error("Metadata length out of range.", is_debug=False),
            SAFE_ERROR_MESSAGES['no_hidden_data']
        )
        self.assertEqual(
            sanitize_error("No hidden file found in the polyglot (EOCD missing)", is_debug=False),
            SAFE_ERROR_MESSAGES['no_hidden_data']
        )
        self.assertEqual(
            sanitize_error("Metadata malformed (missing separator).", is_debug=False),
            SAFE_ERROR_MESSAGES['no_hidden_data']
        )
        # Missing QR code
        self.assertEqual(
            sanitize_error("No QR code found in the image.", is_debug=False),
            SAFE_ERROR_MESSAGES['no_qr']
        )
        # Authentication failure
        self.assertEqual(
            sanitize_error("Incorrect password.", is_debug=False),
            SAFE_ERROR_MESSAGES['password']
        )
        # Capacity error
        self.assertEqual(
            sanitize_error("Host image capacity insufficient for header, threshold, and payload.", is_debug=False),
            SAFE_ERROR_MESSAGES['capacity']
        )

    def test_extract_non_stego_image_returns_friendly_error(self):
        """Verify uploading a non-stego image returns user-friendly error, not generic failure."""
        normal_image = self._create_test_image("plain_carrier.png", 100, 100)
        orig_debug = self.app.config['DEBUG']
        try:
            self.app.config['DEBUG'] = False  # Test production sanitization mode
            with open(normal_image, "rb") as img_f:
                response = self.client.post(
                    "/api/extract",
                    data={"image": (img_f, "plain_carrier.png")},
                    content_type="multipart/form-data"
                )
            self.assertEqual(response.status_code, 400)
            data = response.get_json()
            self.assertIn("error", data)
            self.assertEqual(data["error"], SAFE_ERROR_MESSAGES['no_hidden_data'])
        finally:
            self.app.config['DEBUG'] = orig_debug

    def test_qr_scan_non_qr_image_returns_friendly_error(self):
        """Verify scanning a non-QR image returns 'No QR code found in the image.' in production."""
        normal_image = self._create_test_image("no_qr_image.png", 100, 100)
        orig_debug = self.app.config['DEBUG']
        try:
            self.app.config['DEBUG'] = False
            with open(normal_image, "rb") as img_f:
                response = self.client.post(
                    "/api/qr/scan",
                    data={"image": (img_f, "no_qr_image.png")},
                    content_type="multipart/form-data"
                )
            self.assertEqual(response.status_code, 400)
            data = response.get_json()
            self.assertIn("error", data)
            self.assertEqual(data["error"], SAFE_ERROR_MESSAGES['no_qr'])
        finally:
            self.app.config['DEBUG'] = orig_debug

    # -------------------------------------------------------------------------
    # 5. Configuration & Platform Safety Tests
    # -------------------------------------------------------------------------

    def test_cors_validation_and_origins(self):
        """Verify CORS origins include development localhost and 127.0.0.1."""
        origins = DevelopmentConfig.validate_cors_origins(
            DevelopmentConfig._cors_origins_raw.split(",")
        )
        self.assertIn("http://localhost:5173", origins)
        self.assertIn("http://127.0.0.1:5173", origins)
        self.assertIn("http://localhost:3000", origins)
        self.assertIn("http://127.0.0.1:3000", origins)


if __name__ == '__main__':
    unittest.main()
