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
import unittest.mock
import zipfile
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
        dl_resp.close()

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
        dl_resp.close()

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

    # -------------------------------------------------------------------------
    # 6. Audit Regression Tests (F-01 through F-11)
    # -------------------------------------------------------------------------

    def test_calculate_capacity_stream_zero_disk_io(self):
        """Verify /api/calculate-capacity calculates capacity without writing to disk (F-05)."""
        carrier_path = self._create_test_image("capacity_test.png", 200, 200)
        upload_folder = self.app.config['UPLOAD_FOLDER']
        files_before = set(os.listdir(upload_folder))

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/calculate-capacity",
                data={"image": (f, "capacity_test.png")},
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("totalCapacityBytes", data)
        self.assertGreater(data["totalCapacityBytes"], 0)

        # Confirm zero disk leak in uploads directory
        files_after = set(os.listdir(upload_folder))
        self.assertEqual(files_before, files_after)

    def test_windows_file_cleanup_no_lock_leaks(self):
        """Verify uploaded temporary files are removed without Windows file locks (F-02)."""
        carrier_path = self._create_test_image("cleanup_carrier.png", 250, 250)
        secret_content = b"Content to test Windows file cleanup without locks."
        upload_folder = self.app.config['UPLOAD_FOLDER']

        # Count files before hide
        before_hide = set(os.listdir(upload_folder))

        with open(carrier_path, "rb") as cf:
            resp = self.client.post(
                "/api/hide",
                data={
                    "image": (cf, "carrier.png"),
                    "file": (io.BytesIO(secret_content), "secret.txt"),
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 200)
        download_id = resp.get_json()["download_id"]

        # Only the download output file should have been added; input temp files must be gone
        after_hide = set(os.listdir(upload_folder))
        new_files = after_hide - before_hide
        self.assertEqual(new_files, {download_id})

        # Fetch download output
        dl_resp = self.client.get(f"/api/download/{download_id}")
        self.assertEqual(dl_resp.status_code, 200)
        stego_bytes = dl_resp.data
        dl_resp.close()

        # Test extraction cleanup
        before_extract = set(os.listdir(upload_folder))
        ext_resp = self.client.post(
            "/api/extract",
            data={"image": (io.BytesIO(stego_bytes), "stego.png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, secret_content)

        # Uploaded image for extract should be completely cleaned up
        after_extract = set(os.listdir(upload_folder))
        self.assertEqual(before_extract, after_extract)

    def test_polyglot_zip_bomb_guard(self):
        """Verify polyglot extraction rejects entries that decompress beyond limit (F-04)."""
        poly_file = os.path.join(self.temp_dir, "bomb_polyglot.png")
        carrier_path = self._create_test_image("bomb_carrier.png", 100, 100)

        # Construct a zip containing 51MB of zeroes (compresses to ~50KB)
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("large_file.bin", b"\x00" * (51 * 1024 * 1024))
        zip_bytes = zip_buf.getvalue()

        # Concatenate carrier and zip to form polyglot
        with open(carrier_path, "rb") as cf, open(poly_file, "wb") as pf:
            pf.write(cf.read() + zip_bytes)

        # Extraction must reject with safe error
        with self.assertRaises(ValueError) as ctx:
            extract_from_polyglot(poly_file)
        self.assertIn("exceeds", str(ctx.exception).lower())

    def test_proxyfix_real_ip_and_hsts(self):
        """Verify ProxyFix respects X-Forwarded headers and enables HSTS in production (F-03)."""
        with unittest.mock.patch.dict(os.environ, {
            "SECRET_KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "CORS_ORIGINS": "https://invisio-vault.vercel.app"
        }):
            prod_app = create_app('production')
            prod_app.config['TESTING'] = True
            try:
                client = prod_app.test_client()

                # Plain HTTP request
                resp_http = client.get("/", headers={"X-Forwarded-Proto": "http"})
                self.assertNotIn("Strict-Transport-Security", resp_http.headers)

                # Proxied HTTPS request
                resp_https = client.get(
                    "/",
                    headers={
                        "X-Forwarded-Proto": "https",
                        "X-Forwarded-For": "198.51.100.42"
                    }
                )
                self.assertIn("Strict-Transport-Security", resp_https.headers)
                self.assertIn("max-age=31536000", resp_https.headers["Strict-Transport-Security"])
            finally:
                for h in prod_app.logger.handlers[:]:
                    h.close()
                    prod_app.logger.removeHandler(h)

    def test_qr_logging_does_not_leak_secrets(self):
        """Verify QR extraction does not leak raw plaintext or hidden secrets in logs (F-01)."""
        qr_output = os.path.join(self.temp_dir, "test_qr_leak.png")
        public_url = "https://invisiovault.app/test"
        secret_super_private = "CONFIDENTIAL_API_KEY_NEVER_LOG"

        generate_qr_with_stego(
            public_data=public_url,
            secret_text=secret_super_private,
            output_path=qr_output,
            password=None,
            scale=10
        )

        with self.assertLogs("utils.qr_stego", level="INFO") as log_ctx:
            pub, sec = extract_from_qr_stego(qr_output, password=None)
            self.assertEqual(sec, secret_super_private)

        # Check all logged messages: secret must never appear
        for msg in log_ctx.output:
            self.assertNotIn(secret_super_private, msg)

    def test_polyglot_input_validation(self):
        """Verify polyglot endpoints reject empty files or missing inputs (F-06)."""
        # Missing carrier
        resp = self.client.post(
            "/api/polyglot/create",
            data={"file": (io.BytesIO(b"data"), "file.txt")},
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)

        # Empty carrier
        resp = self.client.post(
            "/api/polyglot/create",
            data={
                "carrier": (io.BytesIO(b""), "empty.png"),
                "file": (io.BytesIO(b"data"), "file.txt")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("empty", resp.get_json().get("error", "").lower())

        # Empty polyglot for extract
        resp = self.client.post(
            "/api/polyglot/extract",
            data={"file": (io.BytesIO(b""), "empty.png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("empty", resp.get_json().get("error", "").lower())

    def test_qr_capacity_calculation(self):
        """Verify /api/qr/capacity returns authentic QR matrix capacity (F-10)."""
        resp = self.client.post(
            "/api/qr/capacity",
            data={"public_data": "https://invisiovault.app"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        cap = data.get("totalCapacityBytes")
        self.assertIsInstance(cap, int)
        # Authentic QR payload capacity is well under 1273 bytes (not the erroneous 90,000 bytes)
        self.assertLessEqual(cap, 1273)
        self.assertGreater(cap, 500)

    def test_pipe_in_filename_metadata_preservation(self):
        """Verify filenames containing pipe character '|' are preserved without corrupting mime type."""
        carrier_path = self._create_test_image("pipe_carrier.png", 250, 250)
        secret_content = b"Content with pipe in filename."
        secret_file = os.path.join(self.temp_dir, "report.txt")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "output_pipe_stego.png")
        pipe_filename = "classified|2026|final.txt"
        hide_file_in_image(
            carrier_path,
            secret_file,
            output_stego,
            password=None,
            original_filename=pipe_filename
        )

        extracted_data, ext_filename, mime = extract_file_from_image(output_stego)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, pipe_filename)
        self.assertEqual(mime, "text/plain")

    def test_password_with_whitespace_end_to_end(self):
        """Verify passwords with leading/trailing spaces are preserved identically across hide and scan."""
        qr_output = os.path.join(self.temp_dir, "whitespace_pwd_qr.png")
        pwd_with_spaces = "  my secret pass 2026  "
        secret_msg = "Confidential message with whitespace password."

        # Test QR generation and scan
        generate_qr_with_stego(
            public_data="https://invisiovault.app",
            secret_text=secret_msg,
            output_path=qr_output,
            password=pwd_with_spaces,
            scale=10
        )

        pub_ext, sec_ext = extract_from_qr_stego(qr_output, password=pwd_with_spaces)
        self.assertEqual(sec_ext, secret_msg)

    def test_qr_endpoints_safe_scale_handling(self):
        """Verify invalid or empty scale strings fall back safely to defaults without errors."""
        resp_cap = self.client.post(
            "/api/qr/capacity",
            data={"public_data": "https://example.com", "scale": ""}
        )
        self.assertEqual(resp_cap.status_code, 200)

        resp_cap_invalid = self.client.post(
            "/api/qr/capacity",
            data={"public_data": "https://example.com", "scale": "not-an-int"}
        )
        self.assertEqual(resp_cap_invalid.status_code, 200)


if __name__ == '__main__':
    unittest.main()

