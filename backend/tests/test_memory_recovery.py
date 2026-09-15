"""Memory recovery, leak detection, and worst-case resource test suite."""
import os
import sys
import gc
import time
import shutil
import tempfile
import unittest
import ctypes
from ctypes import wintypes
import numpy as np
from PIL import Image

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
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

kernel32.GetCurrentProcess.restype = wintypes.HANDLE
psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

def get_rss_mb():
    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
    h = kernel32.GetCurrentProcess()
    psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb)
    return counters.WorkingSetSize / (1024 * 1024)

def get_peak_rss_mb():
    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
    h = kernel32.GetCurrentProcess()
    psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb)
    return counters.PeakWorkingSetSize / (1024 * 1024)


class MemoryRecoveryTests(unittest.TestCase):
    """Verify memory recovery and lack of accumulation across sequential operations."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="iv_mem_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_image(self, path, w=800, h=800):
        arr = np.zeros((h, w, 3), dtype=np.uint8)
        y_idx = np.arange(h, dtype=np.int32)[:, None]
        x_idx = np.arange(w, dtype=np.int32)[None, :]
        arr[:, :, 0] = ((x_idx * 3 + y_idx * 2) % 256).astype(np.uint8)
        arr[:, :, 1] = ((x_idx * 5 + y_idx * 7) % 256).astype(np.uint8)
        arr[:, :, 2] = ((x_idx * 11 + y_idx * 13) % 256).astype(np.uint8)
        img = Image.fromarray(arr, "RGB")
        img.save(path, "PNG")

    def test_01_sequential_stego_memory_recovery(self):
        """Perform 10 sequential hide & extract operations and verify RSS recovers to baseline."""
        from utils.steganography import hide_file_in_image, extract_file_from_image

        gc.collect()
        baseline_rss = get_rss_mb()
        print(f"\n[Memory Test] Initial Baseline RSS: {baseline_rss:.2f} MB")

        rss_history = []
        payload_data = os.urandom(50 * 1024) # 50 KB
        secret_file = os.path.join(self.temp_dir, "secret.bin")
        with open(secret_file, "wb") as f:
            f.write(payload_data)

        carrier_path = os.path.join(self.temp_dir, "carrier.png")
        self._create_image(carrier_path, 800, 800)

        for i in range(10):
            out_path = os.path.join(self.temp_dir, f"stego_{i}.png")
            hide_file_in_image(carrier_path, secret_file, out_path, password="TestPassword123!")
            ext_data, *_ = extract_file_from_image(out_path, password="TestPassword123!")
            self.assertEqual(ext_data, payload_data)
            os.remove(out_path)

            gc.collect()
            current_rss = get_rss_mb()
            rss_history.append(current_rss)

        final_rss = rss_history[-1]
        drift = final_rss - baseline_rss
        print(f"[Memory Test] RSS after 10 cycles: {final_rss:.2f} MB (Drift: {drift:+.2f} MB, Peak: {get_peak_rss_mb():.2f} MB)")
        # Ensure memory does not grow unbounded (drift should be small, < 30 MB)
        self.assertLess(drift, 30.0, f"Excessive memory drift detected: {drift:.2f} MB")

    def test_02_sequential_qr_memory_recovery(self):
        """Perform 15 sequential QR generation & extraction operations."""
        from utils.qr_stego import generate_qr_with_stego, extract_from_qr_stego

        gc.collect()
        baseline_rss = get_rss_mb()

        for i in range(15):
            qr_out = os.path.join(self.temp_dir, f"qr_{i}.png")
            generate_qr_with_stego("https://invisiovault.com", "Confidential QR Secret Data", qr_out, password="TestPassword123!", scale=10)
            pub, sec = extract_from_qr_stego(qr_out, password="TestPassword123!")
            self.assertEqual(sec, "Confidential QR Secret Data")
            os.remove(qr_out)

        gc.collect()
        final_rss = get_rss_mb()
        drift = final_rss - baseline_rss
        print(f"[Memory Test] QR RSS after 15 cycles: {final_rss:.2f} MB (Drift: {drift:+.2f} MB)")
        self.assertLess(drift, 25.0, f"Excessive QR memory drift detected: {drift:.2f} MB")


if __name__ == "__main__":
    unittest.main()
