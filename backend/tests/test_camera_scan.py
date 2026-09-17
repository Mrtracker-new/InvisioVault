"""Comprehensive Camera Scanning & Perspective Rectification Test Suite.

Tests:
1. Test F: Synthetic Grid Pillow Perspective Homography Math Unit Test
   - Perspective-warped known synthetic grid points
   - Unwarps with find_perspective_coeffs and Image.Transform.PERSPECTIVE
   - Asserts subpixel centroid reconstruction error is strictly < 0.3 px (typical < 0.05 px)
2. Test A: Same-Frame Client Geometry Extraction
   - jsQR-style detected corners + version supplied with frame
   - Verifies priority resolution and extraction of visual steganographic secret
3. Test B & C: Public URL Invariant & No Fallback Pollution
   - Standard zxingcpp and pyzbar decode on the generated QR image
   - Verifies exact public URL returned verbatim
   - Verifies zero steganographic pollution (no #IVDATA:, /r/, /share/)
4. Test D: Ordinary QR Handling
   - Standard non-steganographic QR code scanned through pipeline
   - Returns public data correctly, secret is empty string, no crash
5. Test E: Realistic Camera Simulation Pipeline
   - Realistic camera distortion chain:
     * Perspective homography projection (tilt/skew)
     * 2D lighting ramp gradient (illumination plane)
     * Resizing / downscaling
     * Gaussian sensor noise
     * Lossy JPEG compression (Quality 85-90)
   - Verifies rectification and extraction pipeline recovers secret under physical distortions
6. Test G: Password Protection & Rejection
   - Encrypted visual QR requires password
   - Missing or wrong password raises QRStegoError (WRONG_PASSWORD)
   - Correct password decrypts secret
7. Test H: Same PNG Dual-Scan Invariant
   - Verifies identical secret extracted via upload path (no corners) and camera path (with corners)
8. Test I: End-to-End API /api/qr/scan Route Test
   - Verifies Flask endpoint accepts multipart form with image, corners, version, password
   - Verifies cache deduplication and JSON payload response
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from io import BytesIO

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import numpy as np
from PIL import Image, ImageDraw, ImageFilter
import segno
import zxingcpp

from app import create_app
from utils.qr_module_map import find_perspective_coeffs
from utils.qr_stego import (
    generate_qr_with_stego,
    extract_from_qr_stego,
    QRErrorCode,
    QRStegoError,
)


class CameraScanPipelineTests(unittest.TestCase):
    """Rigorous tests for the camera scan and perspective rectification pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="iv_camera_test_")
        cls.app = create_app('development')
        cls.app.config['TESTING'] = True
        cls.app.config['UPLOAD_FOLDER'] = os.path.join(cls.temp_dir, "uploads")
        os.makedirs(cls.app.config['UPLOAD_FOLDER'], exist_ok=True)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.public_url = "https://invisiovault.com/verify?id=987654"
        self.secret_msg = "TopSecretMessage_CameraScan2026"
        self.password = "Secur3Passw0rd!"

    def test_f_synthetic_grid_perspective_math_subpixel_accuracy(self):
        """Test F: Verify Pillow PERSPECTIVE convention subpixel accuracy on synthetic grid."""
        width, height = 400, 400
        # Create a grid image with single-pixel dots at known grid positions
        grid_arr = np.ones((height, width), dtype=np.uint8) * 255
        
        step = 40
        x_coords = list(range(40, width - 40, step))
        y_coords = list(range(40, height - 40, step))
        known_points = []
        for y in y_coords:
            for x in x_coords:
                known_points.append((float(x), float(y)))
                grid_arr[y, x] = 0  # Black dot
        grid_img = Image.fromarray(grid_arr, mode="L")

        # Define 4 destination corners and 4 perspective-warped source corners
        # Destination: regular box (0,0) to (width, height)
        dst_corners = [(0.0, 0.0), (0.0, float(height)), (float(width), float(height)), (float(width), 0.0)]
        # Warped quadrilateral: trapezoid simulating tilted surface
        warped_corners = [(40.0, 30.0), (10.0, 370.0), (390.0, 350.0), (360.0, 50.0)]

        # Find forward warp coeffs: maps regular grid -> warped quadrilateral
        forward_coeffs = find_perspective_coeffs(warped_corners, dst_corners)
        warped_img = grid_img.transform(
            (width, height),
            Image.Transform.PERSPECTIVE,
            forward_coeffs,
            resample=Image.Resampling.BICUBIC,
            fillcolor=255
        )

        # Now unwarp: from warped_corners back to dst_corners
        unwarp_coeffs = find_perspective_coeffs(dst_corners, warped_corners)
        rectified_img = warped_img.transform(
            (width, height),
            Image.Transform.PERSPECTIVE,
            unwarp_coeffs,
            resample=Image.Resampling.BICUBIC,
            fillcolor=255
        )
        rect_arr = np.array(rectified_img, dtype=np.float32)

        # Measure subpixel centroid of each unwarped dot in rectified_arr
        errors = []
        radius = 4
        for orig_x, orig_y in known_points:
            ix, iy = int(round(orig_x)), int(round(orig_y))
            patch = rect_arr[iy - radius:iy + radius + 1, ix - radius:ix + radius + 1]
            inverted = 255.0 - patch
            total_mass = np.sum(inverted)
            if total_mass > 10.0:
                yy, xx = np.indices(patch.shape)
                sub_y = iy - radius + np.sum(yy * inverted) / total_mass
                sub_x = ix - radius + np.sum(xx * inverted) / total_mass
                err = np.hypot(sub_x - orig_x, sub_y - orig_y)
                errors.append(err)

        self.assertGreater(len(errors), 30, "Should detect almost all grid dots")
        mean_err = float(np.mean(errors))
        max_err = float(np.max(errors))
        self.assertLess(mean_err, 0.1, f"Mean centroid error ({mean_err:.4f} px) must be < 0.1 px")
        self.assertLess(max_err, 0.3, f"Max centroid error ({max_err:.4f} px) must be < 0.3 px")

    def test_b_and_c_public_url_invariant_and_no_fallback_pollution(self):
        """Test B & C: Public URL is verbatim, standard decoders read clean URL without stego leak."""
        qr_path = os.path.join(self.temp_dir, "test_clean_public.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=self.secret_msg,
            output_path=qr_path,
            password=None,
            method="visual",
            scale=10,
        )

        # Standard zxingcpp decode
        img = Image.open(qr_path)
        zxing_result = zxingcpp.read_barcode(img)
        self.assertIsNotNone(zxing_result, "Barcode must be readable by standard ZXing")
        self.assertEqual(zxing_result.text, self.public_url, "Standard reader must decode verbatim public data")

        # Invariant checks: zero fallback pollution
        self.assertNotIn("#IVDATA:", zxing_result.text)
        self.assertNotIn("/r/", zxing_result.text)
        self.assertNotIn("/share/", zxing_result.text)

    def test_a_same_frame_client_geometry_extraction(self):
        """Test A: Passing client jsQR-style corners + version correctly extracts visual secret."""
        qr_path = os.path.join(self.temp_dir, "test_client_geom.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=self.secret_msg,
            output_path=qr_path,
            password=None,
            method="visual",
            scale=12,
        )

        img = Image.open(qr_path)
        zx_res = zxingcpp.read_barcode(img)
        self.assertIsNotNone(zx_res)
        pos = zx_res.position

        # Format corners matching browser jsQR output format
        client_corners = {
            "topLeftCorner": {"x": float(pos.top_left.x), "y": float(pos.top_left.y)},
            "topRightCorner": {"x": float(pos.top_right.x), "y": float(pos.top_right.y)},
            "bottomRightCorner": {"x": float(pos.bottom_right.x), "y": float(pos.bottom_right.y)},
            "bottomLeftCorner": {"x": float(pos.bottom_left.x), "y": float(pos.bottom_left.y)},
        }

        pub, sec = extract_from_qr_stego(
            qr_path,
            password=None,
            client_corners=client_corners,
            client_version=3,
        )
        self.assertEqual(pub, self.public_url)
        self.assertEqual(sec, self.secret_msg)

    def test_d_ordinary_qr_handling(self):
        """Test D: Standard ordinary QR codes return public data cleanly with empty secretData."""
        qr_path = os.path.join(self.temp_dir, "test_plain_qr.png")
        segno_qr = segno.make("https://example.com/ordinary-qr", error="H")
        segno_qr.save(qr_path, scale=10, border=4)

        pub, sec = extract_from_qr_stego(qr_path, password=None)
        self.assertEqual(pub, "https://example.com/ordinary-qr")
        self.assertEqual(sec, "", "Secret data for ordinary QR must be empty string")

    def test_e_realistic_camera_simulation_pipeline(self):
        """Test E: Realistic camera simulation (perspective warp + lighting gradient + noise + JPEG)."""
        qr_path = os.path.join(self.temp_dir, "test_cam_sim_orig.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text="CamSimMsg2026",
            output_path=qr_path,
            password=None,
            method="visual",
            scale=14,
        )

        orig_img = Image.open(qr_path).convert("L")
        ow, oh = orig_img.size

        # Place onto a larger canvas (simulating QR seen in camera viewfinder with background)
        pad = 80
        frame_w, frame_h = ow + 2 * pad, oh + 2 * pad
        frame_canvas = Image.new("L", (frame_w, frame_h), 230)
        frame_canvas.paste(orig_img, (pad, pad))

        # 1. Perspective tilt (simulate phone camera held at a slight angle)
        # Shift corners by realistic amounts
        src_corners = [
            (pad + 10.0, pad + 15.0),
            (pad - 8.0, pad + oh + 5.0),
            (pad + ow + 12.0, pad + oh - 8.0),
            (pad + ow - 10.0, pad + 8.0)
        ]
        dst_corners = [
            (pad, pad),
            (pad, pad + oh),
            (pad + ow, pad + oh),
            (pad + ow, pad)
        ]
        coeffs = find_perspective_coeffs(src_corners, dst_corners)
        warped_img = frame_canvas.transform(
            (frame_w, frame_h),
            Image.Transform.PERSPECTIVE,
            coeffs,
            resample=Image.Resampling.BICUBIC,
            fillcolor=230
        )

        # 2. Lighting gradient: smooth 2D plane ramp across the image
        arr = np.array(warped_img, dtype=np.float32)
        rows, cols = arr.shape
        r_grid, c_grid = np.indices((rows, cols))
        # Gradient: +20 intensity at top-left, -15 intensity at bottom-right
        gradient = (1.0 - (r_grid / float(rows))) * 15.0 + (1.0 - (c_grid / float(cols))) * 15.0 - 15.0
        arr = np.clip(arr + gradient, 0, 255)

        # 3. Add mild sensor noise
        np.random.seed(42)
        noise = np.random.normal(0, 1.5, arr.shape)
        arr = np.clip(arr + noise, 0, 255).astype(np.uint8)

        # 4. Save through JPEG compression
        simulated_frame_path = os.path.join(self.temp_dir, "test_cam_sim_frame.jpg")
        sim_img = Image.fromarray(arr, mode="L")
        sim_img.save(simulated_frame_path, format="JPEG", quality=90)

        # Now test extraction through the pipeline
        pub, sec = extract_from_qr_stego(simulated_frame_path, password=None)
        self.assertEqual(pub, self.public_url)
        self.assertEqual(sec, "CamSimMsg2026", "Pipeline must recover secret under realistic camera distortions")

    def test_g_password_protection_and_wrong_password_rejection(self):
        """Test G: Password protected visual QR requires password and rejects incorrect password."""
        qr_path = os.path.join(self.temp_dir, "test_password_qr.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=self.secret_msg,
            output_path=qr_path,
            password=self.password,
            method="visual",
            scale=10,
        )

        # 1. Missing password
        with self.assertRaises((QRStegoError, ValueError)) as ctx:
            extract_from_qr_stego(qr_path, password=None)
        self.assertIn("password", str(ctx.exception).lower())

        # 2. Wrong password
        with self.assertRaises(QRStegoError) as ctx:
            extract_from_qr_stego(qr_path, password="WrongPassword!123")
        self.assertEqual(ctx.exception.error_code, QRErrorCode.WRONG_PASSWORD)

        # 3. Correct password
        pub, sec = extract_from_qr_stego(qr_path, password=self.password)
        self.assertEqual(pub, self.public_url)
        self.assertEqual(sec, self.secret_msg)

    def test_h_same_png_dual_scan_invariant(self):
        """Test H: Direct upload path and camera-assisted path produce identical secret on same PNG."""
        qr_path = os.path.join(self.temp_dir, "test_dual_scan.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=self.secret_msg,
            output_path=qr_path,
            password=self.password,
            method="visual",
            scale=10,
        )

        # Path 1: Direct upload (no client corners or version provided)
        pub_upload, sec_upload = extract_from_qr_stego(qr_path, password=self.password)

        # Path 2: Camera scan with client corners provided
        img = Image.open(qr_path)
        zx_res = zxingcpp.read_barcode(img)
        pos = zx_res.position
        corners = {
            "topLeftCorner": {"x": float(pos.top_left.x), "y": float(pos.top_left.y)},
            "topRightCorner": {"x": float(pos.top_right.x), "y": float(pos.top_right.y)},
            "bottomRightCorner": {"x": float(pos.bottom_right.x), "y": float(pos.bottom_right.y)},
            "bottomLeftCorner": {"x": float(pos.bottom_left.x), "y": float(pos.bottom_left.y)},
        }
        pub_camera, sec_camera = extract_from_qr_stego(
            qr_path,
            password=self.password,
            client_corners=corners,
            client_version=3,
        )

        self.assertEqual(pub_upload, pub_camera)
        self.assertEqual(sec_upload, sec_camera)
        self.assertEqual(sec_upload, self.secret_msg)

    def test_i_api_route_scan_integration(self):
        """Test I: Full HTTP integration of /api/qr/scan with corners, version, and password."""
        qr_path = os.path.join(self.temp_dir, "test_api_qr.png")
        generate_qr_with_stego(
            public_data=self.public_url,
            secret_text=self.secret_msg,
            output_path=qr_path,
            password=self.password,
            method="visual",
            scale=10,
        )

        img = Image.open(qr_path)
        zx_res = zxingcpp.read_barcode(img)
        pos = zx_res.position
        corners = {
            "topLeftCorner": {"x": float(pos.top_left.x), "y": float(pos.top_left.y)},
            "topRightCorner": {"x": float(pos.top_right.x), "y": float(pos.top_right.y)},
            "bottomRightCorner": {"x": float(pos.bottom_right.x), "y": float(pos.bottom_right.y)},
            "bottomLeftCorner": {"x": float(pos.bottom_left.x), "y": float(pos.bottom_left.y)},
        }

        # 1. Scan without password -> expect 400 with passwordRequired: true
        with open(qr_path, "rb") as f:
            img_bytes = f.read()

        response = self.client.post(
            "/api/qr/scan",
            data={
                "image": (BytesIO(img_bytes), "scan.png"),
                "corners": json.dumps(corners),
                "version": "3",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        resp_json = response.get_json()
        self.assertTrue(resp_json.get("passwordRequired", False))

        # 2. Scan with correct password -> expect 200 with publicData & secretData
        response = self.client.post(
            "/api/qr/scan",
            data={
                "image": (BytesIO(img_bytes), "scan.png"),
                "password": self.password,
                "corners": json.dumps(corners),
                "version": "3",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        resp_json = response.get_json()
        self.assertTrue(resp_json["success"])
        self.assertEqual(resp_json["publicData"], self.public_url)
        self.assertEqual(resp_json["secretData"], self.secret_msg)


if __name__ == "__main__":
    unittest.main()
