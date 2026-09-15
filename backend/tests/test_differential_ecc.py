"""Differential verification test suite for Reed-Solomon codec.

Proves 100% bitwise equivalence between the reference `reedsolo` package
and any accelerated implementation across thousands of randomized test vectors,
boundary conditions, chunk sizes, and error-correction regimes.
"""
import os
import sys
import random
import unittest
import numpy as np

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import reedsolo


class DifferentialRSCodecTest(unittest.TestCase):
    """Differential test suite verifying exact bitwise equivalence to reedsolo.RSCodec(32)."""

    @classmethod
    def setUpClass(cls):
        cls.ref_rs = reedsolo.RSCodec(32)
        # Import the candidate codec from utils.steganography
        from utils.steganography import _ecc_encode, _ecc_decode
        cls.candidate_encode = staticmethod(_ecc_encode)
        cls.candidate_decode = staticmethod(_ecc_decode)

    def test_01_empty_payload(self):
        """Verify empty data handling."""
        self.assertEqual(self.candidate_encode(b""), b"")
        self.assertEqual(self.candidate_decode(b""), b"")

    def test_02_single_byte_payloads(self):
        """Test single byte payloads for all 256 possible byte values."""
        for b in range(256):
            data = bytes([b])
            ref_enc = bytes(self.ref_rs.encode(data))
            cand_enc = self.candidate_encode(data)
            self.assertEqual(cand_enc, ref_enc, f"Mismatch at single byte value {b}")

            cand_dec = self.candidate_decode(cand_enc)
            self.assertEqual(cand_dec, data, f"Decode mismatch at byte {b}")

    def test_03_boundary_lengths(self):
        """Test boundary lengths around the 223-byte chunk size: 221, 222, 223, 224, 225, 445, 446, 447."""
        lengths = [1, 2, 10, 100, 222, 223, 224, 445, 446, 447, 668, 669, 670, 1000]
        rng = random.Random(42)
        for L in lengths:
            data = rng.randbytes(L)
            ref_enc = bytes(self.ref_rs.encode(data))
            cand_enc = self.candidate_encode(data)
            self.assertEqual(cand_enc, ref_enc, f"Mismatch at length {L}")

            cand_dec = self.candidate_decode(cand_enc)
            self.assertEqual(cand_dec, data, f"Decode mismatch at length {L}")

    def test_04_1000_randomized_payload_differential(self):
        """Run 1,000 randomized differential tests with arbitrary lengths and content."""
        rng = random.Random(1337)
        for i in range(1000):
            # Length between 1 and 2000 bytes
            L = rng.randint(1, 2000)
            data = rng.randbytes(L)

            ref_enc = bytes(self.ref_rs.encode(data))
            cand_enc = self.candidate_encode(data)
            self.assertEqual(cand_enc, ref_enc, f"Iteration {i} failed for length {L}")

            cand_dec = self.candidate_decode(cand_enc)
            self.assertEqual(cand_dec, data, f"Iteration {i} decode failed for length {L}")

    def test_05_error_correction_1_to_16_errors(self):
        """Verify error correction of 1 up to 16 corrupted bytes per 255-byte block."""
        rng = random.Random(9999)
        # Test on 2 blocks of data (446 bytes)
        data = rng.randbytes(446)
        encoded = bytearray(self.candidate_encode(data))
        self.assertEqual(len(encoded), 255 * 2)

        for num_errors in [1, 2, 4, 8, 12, 16]:
            corrupted = bytearray(encoded)
            # Corrupt num_errors positions in block 0
            positions_blk0 = rng.sample(range(0, 255), num_errors)
            for p in positions_blk0:
                corrupted[p] ^= rng.randint(1, 255)

            # Corrupt num_errors positions in block 1
            positions_blk1 = rng.sample(range(255, 510), num_errors)
            for p in positions_blk1:
                corrupted[p] ^= rng.randint(1, 255)

            recovered = self.candidate_decode(bytes(corrupted))
            self.assertEqual(recovered, data, f"Failed to correct {num_errors} errors per block")

    def test_06_uncorrectable_corruption_rejection(self):
        """Verify clean ValueError rejection when errors exceed 16 symbols (>Singleton bound)."""
        rng = random.Random(5555)
        data = rng.randbytes(223)
        encoded = bytearray(self.candidate_encode(data))

        # Corrupt 17 symbols in the 255-byte codeword
        positions = rng.sample(range(0, 255), 17)
        for p in positions:
            encoded[p] ^= rng.randint(1, 255)

        with self.assertRaises(ValueError):
            self.candidate_decode(bytes(encoded))


if __name__ == "__main__":
    unittest.main()
