"""InvisioVault Comprehensive Performance & Memory Profiler and Benchmark Suite."""
import os
import sys
import time
import io
import gc
import json
import shutil
import tempfile
import ctypes
from ctypes import wintypes
import numpy as np
from PIL import Image

# Ensure backend root is in sys.path
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

def get_mem():
    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
    h = kernel32.GetCurrentProcess()
    psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb)
    return {
        'rss_mb': counters.WorkingSetSize / (1024 * 1024),
        'private_mb': counters.PrivateUsage / (1024 * 1024),
        'peak_rss_mb': counters.PeakWorkingSetSize / (1024 * 1024)
    }

def run_benchmarks():
    results = {}
    print("=" * 70)
    print("INVISIOVAULT PERFORMANCE & MEMORY BASELINE BENCHMARK")
    print("=" * 70)

    # 1. Startup & Baseline Memory
    gc.collect()
    mem_before = get_mem()
    t0 = time.perf_counter()
    from app import create_app
    app = create_app('development')
    t_startup = time.perf_counter() - t0
    mem_after = get_mem()

    results['startup'] = {
        'startup_time_ms': round(t_startup * 1000, 2),
        'baseline_rss_mb': round(mem_after['rss_mb'], 2),
        'baseline_private_mb': round(mem_after['private_mb'], 2)
    }
    print(f"[*] Startup Time: {results['startup']['startup_time_ms']} ms")
    print(f"[*] Baseline RSS: {results['startup']['baseline_rss_mb']} MB")
    print(f"[*] Baseline Private Memory: {results['startup']['baseline_private_mb']} MB")

    from utils.crypto_utils import derive_fernet_key
    from cryptography.fernet import Fernet
    from utils.steganography import hide_file_in_image, extract_file_from_image
    from utils.qr_stego import generate_qr_with_stego, extract_from_qr_stego
    from utils.polyglot import create_polyglot, extract_from_polyglot

    temp_dir = tempfile.mkdtemp(prefix="iv_bench_")
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = os.path.join(temp_dir, "uploads")
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    client = app.test_client()

    # 2. Cryptography Benchmarks
    print("\n--- Cryptography Benchmarks ---")
    results['crypto'] = {}
    salt = os.urandom(16)
    pwd = "BenchmarkSecurePassword123!"

    # KDF Key Derivation
    t0 = time.perf_counter()
    key = derive_fernet_key(pwd, salt)
    t_kdf = time.perf_counter() - t0
    results['crypto']['kdf_time_ms'] = round(t_kdf * 1000, 2)
    print(f"[*] PBKDF2 Key Derivation (480k iter): {results['crypto']['kdf_time_ms']} ms")

    fernet = Fernet(key)
    for size_kb, label in [(10, "10KB"), (1024, "1MB"), (5120, "5MB")]:
        payload = os.urandom(size_kb * 1024)
        gc.collect()
        t0 = time.perf_counter()
        token = fernet.encrypt(payload)
        t_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        decrypted = fernet.decrypt(token)
        t_dec = time.perf_counter() - t0
        assert decrypted == payload

        results['crypto'][label] = {
            'enc_ms': round(t_enc * 1000, 2),
            'dec_ms': round(t_dec * 1000, 2),
            'enc_throughput_mb_s': round((size_kb / 1024) / t_enc, 2),
            'dec_throughput_mb_s': round((size_kb / 1024) / t_dec, 2)
        }
        print(f"[*] Crypto {label}: Encrypt {results['crypto'][label]['enc_ms']} ms, Decrypt {results['crypto'][label]['dec_ms']} ms")

    # 3. QR Stego Benchmarks
    print("\n--- QR Steganography Benchmarks ---")
    results['qr'] = {}
    qr_cases = [
        ("short_50B", "Short secret: 50 bytes of confidential data.", "stream"),
        ("medium_500B", "M" * 500, "stream"),
        ("long_1KB", "L" * 1000, "stream"),
        ("visual_50B", "Visual secret: 50 bytes of secret data.", "visual"),
    ]

    for label, secret_text, mode in qr_cases:
        out_qr = os.path.join(temp_dir, f"qr_{label}.png")
        gc.collect()
        m0 = get_mem()['rss_mb']
        t0 = time.perf_counter()
        generate_qr_with_stego(
            public_data="https://invisiovault.com",
            secret_text=secret_text,
            output_path=out_qr,
            password=pwd,
            method=mode,
            scale=10
        )
        t_gen = time.perf_counter() - t0
        m_gen = get_mem()['rss_mb']

        t0 = time.perf_counter()
        pub, sec = extract_from_qr_stego(out_qr, password=pwd)
        t_dec = time.perf_counter() - t0
        assert sec == secret_text

        results['qr'][label] = {
            'mode': mode,
            'gen_ms': round(t_gen * 1000, 2),
            'dec_ms': round(t_dec * 1000, 2),
            'qr_file_kb': round(os.path.getsize(out_qr) / 1024, 2)
        }
        print(f"[*] QR {label} ({mode}): Gen {results['qr'][label]['gen_ms']} ms, Dec {results['qr'][label]['dec_ms']} ms, File {results['qr'][label]['qr_file_kb']} KB")

    # 4. Steganography Core Benchmarks (Hide & Extract)
    print("\n--- Image Steganography Benchmarks ---")
    results['stego'] = {}

    def create_gradient_carrier(path, w, h):
        arr = np.zeros((h, w, 3), dtype=np.uint8)
        y_idx = np.arange(h, dtype=np.int32)[:, None]
        x_idx = np.arange(w, dtype=np.int32)[None, :]
        arr[:, :, 0] = ((x_idx * 3 + y_idx * 2) % 256).astype(np.uint8)
        arr[:, :, 1] = ((x_idx * 5 + y_idx * 7) % 256).astype(np.uint8)
        arr[:, :, 2] = ((x_idx * 11 + y_idx * 13) % 256).astype(np.uint8)
        img = Image.fromarray(arr, "RGB")
        img.save(path, "PNG")

    stego_cases = [
        ("10KB_in_800x800", 800, 800, 10 * 1024),
        ("100KB_in_1200x1200", 1200, 1200, 100 * 1024),
        ("500KB_in_1600x1600", 1600, 1600, 500 * 1024),
    ]

    for label, w, h, payload_size in stego_cases:
        carrier_path = os.path.join(temp_dir, f"carrier_{label}.png")
        create_gradient_carrier(carrier_path, w, h)
        carrier_mb = round(os.path.getsize(carrier_path) / 1024 / 1024, 2)

        secret_file = os.path.join(temp_dir, f"secret_{label}.bin")
        secret_bytes = os.urandom(payload_size)
        with open(secret_file, "wb") as f:
            f.write(secret_bytes)

        out_stego = os.path.join(temp_dir, f"out_{label}.png")

        gc.collect()
        m_start = get_mem()['rss_mb']
        t0 = time.perf_counter()
        hide_file_in_image(carrier_path, secret_file, out_stego, password=pwd, original_filename=f"secret_{label}.bin")
        t_hide = time.perf_counter() - t0
        m_hide_peak = get_mem()['rss_mb']
        delta_hide_ram = m_hide_peak - m_start

        gc.collect()
        m_extract_start = get_mem()['rss_mb']
        t0 = time.perf_counter()
        ext_data, ext_name, ext_mime = extract_file_from_image(out_stego, password=pwd)
        t_extract = time.perf_counter() - t0
        m_extract_peak = get_mem()['rss_mb']
        delta_extract_ram = m_extract_peak - m_extract_start
        assert ext_data == secret_bytes

        stego_size_mb = round(os.path.getsize(out_stego) / 1024 / 1024, 2)

        results['stego'][label] = {
            'image_dim': f"{w}x{h}",
            'payload_kb': payload_size // 1024,
            'hide_ms': round(t_hide * 1000, 2),
            'extract_ms': round(t_extract * 1000, 2),
            'carrier_size_mb': carrier_mb,
            'stego_size_mb': stego_size_mb,
            'delta_hide_ram_mb': round(delta_hide_ram, 2),
            'delta_extract_ram_mb': round(delta_extract_ram, 2),
            'current_rss_mb': round(get_mem()['rss_mb'], 2)
        }
        print(f"[*] Stego {label}: Hide {results['stego'][label]['hide_ms']} ms (RAM +{results['stego'][label]['delta_hide_ram_mb']} MB), Extract {results['stego'][label]['extract_ms']} ms (RAM +{results['stego'][label]['delta_extract_ram_mb']} MB)")

    # 5. Polyglot Benchmarks
    print("\n--- Polyglot Benchmarks ---")
    results['polyglot'] = {}
    for size_kb, label in [(100, "100KB"), (1024, "1MB"), (5120, "5MB")]:
        c_path = os.path.join(temp_dir, f"poly_carrier_{label}.jpg")
        with open(c_path, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF" + os.urandom(size_kb * 1024))

        p_file = os.path.join(temp_dir, f"poly_payload_{label}.bin")
        p_bytes = os.urandom(size_kb * 1024)
        with open(p_file, "wb") as f:
            f.write(p_bytes)

        out_poly = os.path.join(temp_dir, f"out_poly_{label}.jpg")

        gc.collect()
        m_start = get_mem()['rss_mb']
        t0 = time.perf_counter()
        create_polyglot(c_path, p_file, out_poly, password=pwd, original_filename=f"poly_payload_{label}.bin")
        t_create = time.perf_counter() - t0
        m_create = get_mem()['rss_mb']

        gc.collect()
        t0 = time.perf_counter()
        ext_p, ext_name = extract_from_polyglot(out_poly, password=pwd)
        t_ext = time.perf_counter() - t0
        assert ext_p == p_bytes

        results['polyglot'][label] = {
            'create_ms': round(t_create * 1000, 2),
            'extract_ms': round(t_ext * 1000, 2),
            'file_size_mb': round(os.path.getsize(out_poly) / 1024 / 1024, 2)
        }
        print(f"[*] Polyglot {label}: Create {results['polyglot'][label]['create_ms']} ms, Extract {results['polyglot'][label]['extract_ms']} ms")

    # 6. API Latency Benchmarks
    print("\n--- API Endpoint Latencies ---")
    results['api'] = {}

    # Health
    t0 = time.perf_counter()
    for _ in range(10):
        resp = client.get('/api/health')
        assert resp.status_code == 200
    results['api']['health_avg_ms'] = round((time.perf_counter() - t0) / 10 * 1000, 2)
    print(f"[*] /api/health: {results['api']['health_avg_ms']} ms")

    # QR Detect
    qr_sample_path = os.path.join(temp_dir, "qr_short_50B.png")
    with open(qr_sample_path, "rb") as f:
        qr_bytes = f.read()

    t0 = time.perf_counter()
    for _ in range(5):
        resp = client.post('/api/qr/detect', data={'image': (io.BytesIO(qr_bytes), 'qr.png')}, content_type='multipart/form-data')
        assert resp.status_code == 200
    results['api']['qr_detect_avg_ms'] = round((time.perf_counter() - t0) / 5 * 1000, 2)
    print(f"[*] /api/qr/detect: {results['api']['qr_detect_avg_ms']} ms")

    # Clean up temp
    shutil.rmtree(temp_dir, ignore_errors=True)

    results['final_memory'] = get_mem()
    print("\n" + "=" * 70)
    print(f"FINAL PROCESS RSS: {round(results['final_memory']['rss_mb'], 2)} MB (Peak Working Set: {round(results['final_memory']['peak_rss_mb'], 2)} MB)")
    print("=" * 70)

    out_file = sys.argv[1] if len(sys.argv) > 1 else os.getenv("BENCHMARK_OUT", "benchmark_optimized.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Benchmark results saved to {out_file}")

if __name__ == "__main__":
    run_benchmarks()
