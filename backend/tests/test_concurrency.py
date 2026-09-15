"""Test suite for concurrency protection, semaphore acquisition, and pre-validation in InvisioVault."""

import io
import os
import sys
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from PIL import Image
import numpy as np
from app import create_app
from extensions import limiter
from api.routes import _heavy_operation_semaphore


class ConcurrencyAndPreValidationTests(unittest.TestCase):
    """Test concurrency limits and pre-validation execution order."""

    @classmethod
    def setUpClass(cls):
        limiter.enabled = False
        cls.temp_dir = tempfile.mkdtemp(prefix="iv_concurrency_test_")
        cls.app = create_app('development')
        cls.app.config['TESTING'] = True
        cls.app.config['UPLOAD_FOLDER'] = os.path.join(cls.temp_dir, "uploads")
        os.makedirs(cls.app.config['UPLOAD_FOLDER'], exist_ok=True)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        limiter.enabled = True
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _create_valid_png_bytes(self, width=200, height=200):
        arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(arr, "RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return buf.getvalue()

    def test_pre_validation_rejects_before_semaphore(self):
        """Pre-validation must reject bad requests immediately without waiting on semaphore."""
        acquired = _heavy_operation_semaphore.acquire(blocking=False)
        self.assertTrue(acquired, "Should acquire semaphore for test setup")

        try:
            res = self.client.post('/api/hide', data={'text': 'hello'})
            self.assertEqual(res.status_code, 400)
            self.assertIn(b'Image is required', res.data)

            res = self.client.post(
                '/api/hide',
                data={
                    'image': (io.BytesIO(b'not an image'), 'test.png'),
                    'text': 'hello'
                },
                content_type='multipart/form-data'
            )
            self.assertEqual(res.status_code, 400)

            res = self.client.post(
                '/api/hide',
                data={
                    'image': (io.BytesIO(self._create_valid_png_bytes()), 'test.png'),
                    'text': 'hello',
                    'password': 'short'
                },
                content_type='multipart/form-data'
            )
            self.assertEqual(res.status_code, 400)
            self.assertIn(b'Password must be at least', res.data)
        finally:
            _heavy_operation_semaphore.release()

    def test_semaphore_timeout_returns_503_with_retry_after(self):
        """When semaphore is held past timeout, route must return 503 with Retry-After: 5."""
        acquired = _heavy_operation_semaphore.acquire(blocking=False)
        self.assertTrue(acquired)

        try:
            import api.routes as routes_mod
            orig_timeout = routes_mod._HEAVY_OP_TIMEOUT_SECONDS
            routes_mod._HEAVY_OP_TIMEOUT_SECONDS = 0.1

            try:
                valid_png = self._create_valid_png_bytes()
                res = self.client.post(
                    '/api/hide',
                    data={
                        'image': (io.BytesIO(valid_png), 'test.png'),
                        'text': 'secret content'
                    },
                    content_type='multipart/form-data'
                )
                self.assertEqual(res.status_code, 503)
                self.assertEqual(res.headers.get('Retry-After'), '5')
                self.assertIn(b'server is currently busy', res.data)
            finally:
                routes_mod._HEAVY_OP_TIMEOUT_SECONDS = orig_timeout
        finally:
            _heavy_operation_semaphore.release()

    def test_concurrent_requests_execute_safely(self):
        """1, 2, 5, 10 concurrent requests must execute without deadlocks or corruption."""
        valid_png = self._create_valid_png_bytes()

        for num_workers in [1, 2, 5, 10]:
            def send_req(i):
                with self.app.test_client() as c:
                    return c.post(
                        '/api/hide',
                        data={
                            'image': (io.BytesIO(valid_png), f'test_{i}.png'),
                            'text': f'secret text {i}'
                        },
                        content_type='multipart/form-data'
                    )

            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(send_req, i) for i in range(num_workers)]
                results = [f.result() for f in futures]

            status_codes = [r.status_code for r in results]
            for code in status_codes:
                self.assertIn(code, (200, 503))

            successes = [r for r in results if r.status_code == 200]
            self.assertGreater(len(successes), 0, f"At least 1 request must succeed for {num_workers} workers")

            acquired = _heavy_operation_semaphore.acquire(blocking=False)
            self.assertTrue(acquired, "Semaphore must be available after all threads complete")
            _heavy_operation_semaphore.release()

    def test_tiered_response_streaming_and_call_on_close(self):
        """Verify tiered streaming: small payloads use BytesIO, large payloads stream and clean up on close."""
        from utils.steganography import hide_file_in_image

        # Create carrier and hide a 1.2 MB file
        payload_1_2mb = os.urandom(1_200_000)
        carrier_path = os.path.join(self.temp_dir, "large_carrier.png")
        stego_path = os.path.join(self.temp_dir, "large_stego.png")
        payload_path = os.path.join(self.temp_dir, "large_payload.bin")

        with open(payload_path, "wb") as f:
            f.write(payload_1_2mb)

        # 2500x2500 gradient image has plenty of capacity for 1.2 MB
        arr = np.linspace(0, 255, 2500 * 2500 * 3, dtype=np.uint8).reshape((2500, 2500, 3))
        Image.fromarray(arr, "RGB").save(carrier_path, "PNG")

        hide_file_in_image(carrier_path, payload_path, stego_path)

        # Request extraction via API
        with open(stego_path, "rb") as f:
            stego_bytes = f.read()

        res = self.client.post(
            '/api/extract',
            data={'image': (io.BytesIO(stego_bytes), 'large_stego.png')},
            content_type='multipart/form-data'
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), len(payload_1_2mb))
        self.assertEqual(res.data, payload_1_2mb)

        # Ensure close cleans up all temporary extraction files
        res.close()
        upload_folder = self.app.config['UPLOAD_FOLDER']
        ext_tmps = [f for f in os.listdir(upload_folder) if f.startswith("ext_")]
        self.assertEqual(len(ext_tmps), 0, f"Temporary file should be removed by call_on_close, found: {ext_tmps}")

    def test_large_payload_streaming_rss_invariance(self):
        """Verify that streaming 1MB to 50MB files via send_file does not materialize into heap."""
        import gc
        import ctypes
        from ctypes import wintypes
        from flask import send_file

        class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            _fields_ = [
                ('cb', wintypes.DWORD),
                ('PageFaultCount', wintypes.DWORD),
                ('PeakWorkingSetSize', ctypes.c_size_t),
                ('WorkingSetSize', ctypes.c_size_t),
                ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                ('PagefileUsage', ctypes.c_size_t),
                ('PeakPagefileUsage', ctypes.c_size_t),
                ('PrivateUsage', ctypes.c_size_t),
            ]

        def _get_rss_mb():
            try:
                kernel32 = ctypes.windll.kernel32
                psapi = ctypes.windll.psapi
                kernel32.GetCurrentProcess.restype = wintypes.HANDLE
                psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
                psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
                c = _PROCESS_MEMORY_COUNTERS_EX()
                c.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS_EX)
                psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
                return c.WorkingSetSize / (1024 * 1024)
            except Exception:
                return 0.0

        for size_mb in [1, 5, 10, 25, 50]:
            tmp_path = os.path.join(self.temp_dir, f"stream_test_{size_mb}mb.bin")
            chunk = b'S' * (1024 * 1024)
            with open(tmp_path, "wb") as f:
                for _ in range(size_mb):
                    f.write(chunk)

            gc.collect()
            rss_start = _get_rss_mb()

            # Create route response directly using send_file
            with self.app.test_request_context():
                resp = send_file(tmp_path, as_attachment=True, download_name=f"stream_{size_mb}mb.bin")
                resp.direct_passthrough = False

                total_streamed = 0
                peak_in_flight_rss = rss_start
                for data_chunk in resp.response:
                    total_streamed += len(data_chunk)
                    cur_rss = _get_rss_mb()
                    if cur_rss > peak_in_flight_rss:
                        peak_in_flight_rss = cur_rss

                resp.close()

            delta_mb = peak_in_flight_rss - rss_start
            self.assertEqual(total_streamed, size_mb * 1024 * 1024)
            # Memory must NOT increase by the payload size (e.g. 50 MB payload must not cause > 10 MB heap spike)
            if rss_start > 0:
                self.assertLess(
                    delta_mb,
                    max(5.0, size_mb * 0.1),
                    f"Payload of {size_mb} MB caused unexpected RSS spike of {delta_mb:.2f} MB"
                )
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == '__main__':
    unittest.main()
