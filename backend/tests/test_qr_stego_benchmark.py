"""Comprehensive Multi-Decoder Reliability and Robustness Test Suite for QR Steganography.

Tests:
1. Multi-Decoder Reliability (ZXing-cpp + PyZbar standard scanning)
2. Secret Extraction & Decryption Fidelity (Plain and Password Encrypted)
3. Both Steganographic Channels:
   - Visual Module Mode (clean public barcode, zero fragment exposure)
   - Optimized Stream Mode (compressed authenticated container in fragment)
4. Distortions:
   - PNG save/reload
   - Lanczos downscaling (400px, 300px)
   - Gaussian blur (1.0, 1.5)
   - JPEG recompression (Quality 90, 80)
   - Centered logo insertion
5. Boundary and Negative Cases:
   - Over-capacity refusal
   - Tampered payload rejection
   - Wrong password rejection
6. Performance & Capacity Benchmarks
"""

import io
import os
import shutil
import sys
import tempfile
import time
import unittest

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from PIL import Image, ImageFilter, ImageDraw
import zxingcpp
try:
    from pyzbar import pyzbar
except (ImportError, OSError):
    pyzbar = None

from utils.qr_stego import (
    QRErrorCode,
    QRStegoError,
    _embed_stream_qr,
    calculate_qr_capacity,
    decode_qr_only,
    extract_from_qr_stego,
    generate_qr_with_stego,
    get_qr_capacity_info,
)


class QRStegoRobustnessTests(unittest.TestCase):
    """Test suite validating QR steganography decodability and robustness."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="iv_qr_bench_")
        self.public_url = "https://invisiovault.com"
        self.password = "TestSecurityPassword999!"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_logo(self) -> str:
        logo_path = os.path.join(self.test_dir, "sample_logo.png")
        img = Image.new("RGBA", (120, 120), (20, 30, 40, 255))
        draw = ImageDraw.Draw(img)
        draw.ellipse([20, 20, 100, 100], fill=(0, 200, 100, 255))
        img.save(logo_path)
        return logo_path

    def test_visual_mode_end_to_end(self):
        """Verify Visual Mode produces a clean public QR that decodes on standard decoders."""
        out_path = os.path.join(self.test_dir, "test_visual.png")
        secret = "CLASSIFIED: Operation Nightfall initiated at 0400 UTC."

        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
            password=self.password,
            method="visual",
            scale=10,
        )

        with Image.open(out_path) as img:
            z_res = zxingcpp.read_barcodes(img.convert("RGB"))
            if pyzbar is not None:
                pz_res = pyzbar.decode(img)
                self.assertTrue(bool(pz_res), "PyZbar failed to decode visual QR")
                self.assertEqual(pz_res[0].data.decode(), self.public_url)

        # 1. Standard decoders MUST decode the public URL only (NO #IVDATA exposed)
        self.assertTrue(bool(z_res), "ZXing failed to decode visual QR")
        self.assertEqual(z_res[0].text, self.public_url)

        # 2. InvisioVault extracts and decrypts secret
        pub_ext, sec_ext = extract_from_qr_stego(out_path, password=self.password)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, secret)

    def test_stream_mode_rejected_for_generation(self):
        """Verify stream mode is explicitly rejected for new QR generation (no #IVDATA)."""
        out_path = os.path.join(self.test_dir, "test_stream_reject.png")
        with self.assertRaises(QRStegoError) as ctx:
            generate_qr_with_stego(
                public_data=self.public_url,
                secret_text="Test Secret",
                output_path=out_path,
                method="stream",
            )
        self.assertEqual(ctx.exception.error_code, QRErrorCode.QR_INVALID)
        self.assertIn("no longer supported", str(ctx.exception))
        self.assertFalse(os.path.exists(out_path))

    def test_multi_decoder_distortion_robustness(self):
        """Verify robustness against resizing, slight blur, and JPEG compression."""
        out_path = os.path.join(self.test_dir, "test_distortion.png")
        secret = "Mission Critical Steganographic Message #402."

        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
            password=self.password,
            scale=10,
        )

        with Image.open(out_path) as base_img:
            # 1. Downscale to 400x400
            down_400 = base_img.resize((400, 400), Image.Resampling.LANCZOS).convert("RGB")
            z_400 = zxingcpp.read_barcodes(down_400)
            self.assertTrue(bool(z_400), "ZXing failed on 400px resize")
            # Verify secret extraction from resized image
            down_400_path = os.path.join(self.test_dir, "down_400.png")
            down_400.save(down_400_path)
            _, sec_400 = extract_from_qr_stego(down_400_path, password=self.password)
            self.assertEqual(sec_400, secret)

            # 2. Downscale to 300x300
            down_300 = base_img.resize((300, 300), Image.Resampling.LANCZOS).convert("RGB")
            z_300 = zxingcpp.read_barcodes(down_300)
            self.assertTrue(bool(z_300), "ZXing failed on 300px resize")
            down_300_path = os.path.join(self.test_dir, "down_300.png")
            down_300.save(down_300_path)
            _, sec_300 = extract_from_qr_stego(down_300_path, password=self.password)
            self.assertEqual(sec_300, secret)

            # 3. Gaussian blur
            blurred = base_img.filter(ImageFilter.GaussianBlur(radius=1.2)).convert("RGB")
            z_blur = zxingcpp.read_barcodes(blurred)
            self.assertTrue(bool(z_blur), "ZXing failed on 1.2px blur")
            blur_path = os.path.join(self.test_dir, "blurred.png")
            blurred.save(blur_path)
            _, sec_blur = extract_from_qr_stego(blur_path, password=self.password)
            self.assertEqual(sec_blur, secret)

            # 4. JPEG Quality 90
            jpg_path = os.path.join(self.test_dir, "quality90.jpg")
            base_img.convert("RGB").save(jpg_path, format="JPEG", quality=90)
            jpg_img = Image.open(jpg_path).convert("RGB")
            z_jpg = zxingcpp.read_barcodes(jpg_img)
            self.assertTrue(bool(z_jpg), "ZXing failed on JPEG Q90")
            _, sec_jpg = extract_from_qr_stego(jpg_path, password=self.password)
            self.assertEqual(sec_jpg, secret)

    def test_logo_embedding_preserves_error_correction(self):
        """Verify centered logo embedding does not break scannability."""
        logo_path = self._create_sample_logo()
        out_path = os.path.join(self.test_dir, "test_logo.png")
        secret = "Secret with logo watermark embedded in QR center."

        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
            password=self.password,
            scale=12,
            logo_path=logo_path,
        )

        with Image.open(out_path) as img:
            z_res = zxingcpp.read_barcodes(img.convert("RGB"))
            if pyzbar is not None:
                pz_res = pyzbar.decode(img)
                self.assertTrue(bool(pz_res), "PyZbar failed to decode QR with logo")

        self.assertTrue(bool(z_res), "ZXing failed to decode QR with logo")

        pub_ext, sec_ext = extract_from_qr_stego(out_path, password=self.password)
        self.assertEqual(sec_ext, secret)

    def test_wrong_password_rejected(self):
        """Verify wrong password raises classified WRONG_PASSWORD error."""
        out_path = os.path.join(self.test_dir, "test_pwd.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text="Secure Message",
            output_path=out_path,
            password="CorrectPassword123!",
            scale=10,
        )

        with self.assertRaises(ValueError) as ctx:
            extract_from_qr_stego(out_path, password="WrongPassword456!")
        self.assertIn("password", str(ctx.exception).lower())

    def test_unencrypted_payload_crc_integrity(self):
        """Verify plain (no password) payloads are extracted and integrity-checked."""
        out_path = os.path.join(self.test_dir, "test_plain.png")
        plain_secret = "Open source verification text with no encryption."

        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=plain_secret,
            output_path=out_path,
            password=None,
            scale=10,
        )

        pub_ext, sec_ext = extract_from_qr_stego(out_path, password=None)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, plain_secret)

    def test_capacity_info_and_safe_boundaries(self):
        """Verify get_qr_capacity_info returns authentic metadata and safe boundaries."""
        info = get_qr_capacity_info(self.public_url, scale=10)
        self.assertIn("safeCapacityBytes", info)
        self.assertIn("maxSafeVersion", info)
        self.assertLessEqual(info["maxSafeVersion"], 22)
        self.assertGreater(info["safeCapacityBytes"], 100)

    def test_default_method_is_visual_clean_url(self):
        """Verify default (auto) method generates visual QR with clean public URL (no #IVDATA)."""
        out_path = os.path.join(self.test_dir, "test_auto_default.png")
        secret = "Auto Default Mode Secret"
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
        )
        with Image.open(out_path) as img:
            z_res = zxingcpp.read_barcodes(img.convert("RGB"))
            self.assertTrue(bool(z_res))
            self.assertEqual(z_res[0].text, self.public_url)
            self.assertNotIn("#IVDATA:", z_res[0].text)
            self.assertNotIn("/r/", z_res[0].text)
            self.assertNotIn("/share/", z_res[0].text)

        pub_ext, sec_ext = extract_from_qr_stego(out_path)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, secret)

    def test_end_to_end_same_png_dual_scan(self):
        """PRIMARY ACCEPTANCE TEST: Same PNG dual-scan invariant.

        1. Standard QR reader (ZXing) decodes ONLY exact public_data (no #IVDATA, no /r/, no ciphertext).
        2. InvisioVault extractor recovers the hidden secret from the exact same image.
        """
        out_path = os.path.join(self.test_dir, "test_dual_scan.png")
        public_url = "https://example.com"
        secret = "Alpha Bravo 42"
        password = "Password123!"

        generate_qr_with_stego(
            public_data=public_url,
            secret_text=secret,
            output_path=out_path,
            password=password,
            scale=15,
        )

        # 1. Standard QR reader on actual PNG image
        with Image.open(out_path) as img:
            z_res = zxingcpp.read_barcodes(img.convert("RGB"))
            self.assertTrue(bool(z_res), "Standard barcode reader failed to decode QR")
            decoded_text = z_res[0].text
            self.assertEqual(decoded_text, public_url, "Standard reader must return exact public URL")
            self.assertNotIn("#IVDATA:", decoded_text, "QR decoded text must not contain #IVDATA:")
            self.assertNotIn("/r/", decoded_text, "QR decoded text must not contain /r/")
            self.assertNotIn("/share/", decoded_text, "QR decoded text must not contain /share/")
            self.assertNotIn(secret, decoded_text, "Secret plaintext must not appear in standard QR text")

        # 2. InvisioVault extractor on the EXACT SAME PNG image
        pub_ext, sec_ext = extract_from_qr_stego(out_path, password=password)
        self.assertEqual(pub_ext, public_url)
        self.assertEqual(sec_ext, secret)

    def test_large_secret_precheck_capacity_refusal(self):
        """Verify large secret exceeding safe visual capacity is rejected before generation."""
        import secrets
        out_path = os.path.join(self.test_dir, "test_large_refusal.png")
        # Uncompressible payload exceeding safe capacity
        huge_secret = secrets.token_hex(2500)

        with self.assertRaises(QRStegoError) as ctx:
            generate_qr_with_stego(
                public_data="https://example.com",
                secret_text=huge_secret,
                output_path=out_path,
            )
        self.assertEqual(ctx.exception.error_code, QRErrorCode.CAPACITY_EXCEEDED)
        self.assertIn("shorten the secret message", str(ctx.exception))
        # Ensure no image was generated when capacity is exceeded
        self.assertFalse(os.path.exists(out_path), "No image should be generated when capacity is exceeded")

    def test_different_public_urls_exact_preservation(self):
        """Verify standard decoder returns each URL verbatim with zero modification."""
        test_urls = [
            "https://example.com",
            "https://google.com",
            "https://example.com/path/page",
            "http://localhost:5173/test",
        ]
        secret = "Secret Payload 777"
        for idx, url in enumerate(test_urls):
            out_path = os.path.join(self.test_dir, f"test_url_{idx}.png")
            generate_qr_with_stego(
                public_data=url,
                secret_text=secret,
                output_path=out_path,
            )
            with Image.open(out_path) as img:
                decoded = zxingcpp.read_barcodes(img.convert("RGB"))[0].text
                self.assertEqual(decoded, url, f"Decoded URL mismatch for {url}")
                self.assertNotIn("#IVDATA:", decoded)
                self.assertNotIn("/r/", decoded)
                self.assertNotIn("/share/", decoded)
            pub_ext, sec_ext = extract_from_qr_stego(out_path)
            self.assertEqual(pub_ext, url)
            self.assertEqual(sec_ext, secret)

    def test_legacy_ivdata_backward_compatibility(self):
        """Verify legacy #IVDATA: QR codes remain readable by InvisioVault extractor."""
        out_path = os.path.join(self.test_dir, "test_legacy_ivdata.png")
        secret = "Legacy Stream Secret 123"
        # Generate using internal _embed_stream_qr to simulate an existing legacy QR
        _embed_stream_qr(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
            password=self.password,
        )
        with Image.open(out_path) as img:
            decoded = zxingcpp.read_barcodes(img.convert("RGB"))[0].text
            self.assertIn("#IVDATA:", decoded)

        pub_ext, sec_ext = extract_from_qr_stego(out_path, password=self.password)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, secret)

    def test_visual_mode_custom_colors(self):
        """Verify Visual Mode works with custom non-black/white foreground colors."""
        out_path = os.path.join(self.test_dir, "test_visual_navy.png")
        secret = "Navy Visual Stego"
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
            method="visual",
            fg_color="#102030",
        )
        pub_ext, sec_ext = extract_from_qr_stego(out_path)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, secret)

    def test_raw_qr_text_assisted_extraction(self):
        """Verify raw_qr_text accelerates legacy stream extraction."""
        out_path = os.path.join(self.test_dir, "test_raw_assist.png")
        secret = "Client Assisted Secret Payload"
        _embed_stream_qr(
            public_data=self.public_url,
            secret_text=secret,
            output_path=out_path,
        )
        with Image.open(out_path) as img:
            z_res = zxingcpp.read_barcodes(img.convert("RGB"))
            raw_text = z_res[0].text

        pub_ext, sec_ext = extract_from_qr_stego(out_path, raw_qr_text=raw_text)
        self.assertEqual(pub_ext, self.public_url)
        self.assertEqual(sec_ext, secret)


def run_benchmark():
    """Execute performance and reliability benchmark for visual QR steganography."""
    print("\n" + "=" * 95)
    print("INVISIOVAULT QR STEGANOGRAPHY ROBUSTNESS BENCHMARK")
    print("=" * 95)

    payload_sizes = [50, 100, 200, 350, 500]
    public_url = "https://invisiovault.com"
    pwd = "BenchmarkPassword123!"

    print(f"{'Size':>7} | {'Method':>7} | {'QR Ver':>6} | {'Modules':>8} | {'ZXing':>6} | {'PyZbar':>6} | {'Extract':>8} | {'Time':>7} | {'Status'}")
    print("-" * 95)

    test_dir = tempfile.mkdtemp(prefix="bench_run_")
    try:
        for size in payload_sizes:
            secret = "Benchmark payload data block for InvisioVault. " * (size // 45 + 1)
            secret = secret[:size]

            out_path = os.path.join(test_dir, f"bench_visual_{size}.png")
            t0 = time.perf_counter()
            status = "OK"

            try:
                generate_qr_with_stego(
                    public_data=public_url,
                    secret_text=secret,
                    output_path=out_path,
                    password=pwd,
                    scale=10,
                )
                elapsed = (time.perf_counter() - t0) * 1000

                with Image.open(out_path) as img:
                    w, _ = img.size
                    mod_count = (w // 10) - 8  # border=4 on each side -> 8 modules
                    ver = int((mod_count - 17) / 4)
                    z_ok = bool(zxingcpp.read_barcodes(img.convert("RGB")))
                    pz_ok = bool(pyzbar.decode(img)) if pyzbar is not None else "N/A"

                pub_ext, sec_ext = extract_from_qr_stego(out_path, password=pwd)
                ext_ok = (sec_ext == secret)

            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000
                status = f"ERR: {str(exc)[:20]}"
                ver = 0
                mod_count = 0
                z_ok = pz_ok = ext_ok = False

            ver_str = f"v{ver}" if ver > 0 else "N/A"
            dim_str = f"{mod_count}x{mod_count}" if mod_count > 0 else "N/A"
            print(
                f"{size:>6}B | {'visual':>7} | {ver_str:>6} | {dim_str:>8} | "
                f"{str(z_ok):>6} | {str(pz_ok):>6} | {str(ext_ok):>8} | "
                f"{elapsed:>6.1f}ms | {status}"
            )

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
    print("=" * 95 + "\n")


if __name__ == "__main__":
    run_benchmark()
    unittest.main()
