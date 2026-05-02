import numpy as np

"""
1. The Cosine LSH functionality
"""

class CosineLSH:

    def __init__(self, hashed_bits, dimension, seed=None):
        #---------------- Avoid High Dimensionality, use JL Lemma to reduce dimension----------------
        rng = np.random.default_rng(seed)

        #-------------------------- this part defines all the standard LSH mechanism -------------------
        self.num_bits = hashed_bits
        self.dimension = dimension

        # Generate random hyperplanes
        self.hyperplanes = rng.standard_normal(size=(hashed_bits, dimension))

        norms = np.linalg.norm(self.hyperplanes, axis=1, keepdims=True)

        # Avoid division by zero (unlikely with Gaussian, but good practice)
        norms[norms == 0] = 1

        self.hyperplanes = self.hyperplanes / norms

        self.filtered_indices = None
        self.clean_mask = None
        # Cache for quantized+normalized hyperplanes keyed by k_bits.
        # Hyperplanes are fixed after __init__, so quantization is a one-time cost.
        self._unit_hp_cache = {}
    
    def _unit_hyperplanes(self, k_bits=None):
        """Return unit-norm hyperplanes, quantized if k_bits given. Result is cached."""
        if k_bits is None:
            return self.hyperplanes  # already unit-norm from __init__
        if k_bits not in self._unit_hp_cache:
            qhp = self.quantize_array(self.hyperplanes, k_bits).astype(np.float64)
            norms = np.linalg.norm(qhp, axis=1, keepdims=True)
            norms[norms == 0] = 1
            self._unit_hp_cache[k_bits] = qhp / norms
        return self._unit_hp_cache[k_bits]

    @staticmethod
    def to_fixed_width(n, bit_width):
        # Create a mask of all 1s for the desired width
        mask = (1 << bit_width) - 1
        # Force the number into that width
        return n & mask
    
    @staticmethod
    def quantize_array(arr, k: int):
        """
        Quantizes a real-number array (1D vector or 2D matrix) into a k-bit signed integer array.
        Uses max-scaling to prevent zero-collapse at extremely low bit depths.
        """
        M = (1 << (k - 1)) - 1
        
        # Scale the array so its largest absolute value is exactly 1.0.
        # This prevents 2-bit or 3-bit quantization from collapsing everything to 0.
        max_val = np.max(np.abs(arr))
        if max_val > 0:
            arr_scaled = arr / max_val
        else:
            arr_scaled = arr
            
        # FIXED: Enforce 64-bit integers to prevent dot-product overflow at 16-bit!
        v_quantized = np.round(arr_scaled * M).astype(np.int64)
        v_quantized = np.clip(v_quantized, -M, M)
        
        return v_quantized

    def hash(self, vector, k_bits=None):
        if k_bits is not None:
            vector = self.quantize_array(vector, k_bits)
        active_hp = self._unit_hyperplanes(k_bits)

        # Project onto all hyperplanes in one BLAS call
        projections = np.dot(active_hp, vector)

        signs = (projections >= 0).view(np.uint8)

        # Pack all bits at once with np.packbits instead of a Python for loop
        packed = np.packbits(signs)
        hash_code = int.from_bytes(packed.tobytes(), 'big')
        # packbits zero-pads to the next byte boundary; shift off the padding
        padding = len(packed) * 8 - self.num_bits
        return self.to_fixed_width(hash_code >> padding, self.num_bits)
    
    def filter_by_hyperplane(self, vector, num_vec, k_bits=None):
        if k_bits is not None:
            vector = self.quantize_array(vector, k_bits)
        active_hp = self._unit_hyperplanes(k_bits)  # cached, unit-norm

        norm_vec = np.linalg.norm(vector)
        if norm_vec == 0:
            self.filtered_indices = np.array([], dtype=int)
            self.clean_mask = (1 << self.num_bits) - 1
            return self.filtered_indices

        unit_vec = vector / norm_vec

        # Cosine similarity: active_hp is already unit-norm
        cos_theta = np.dot(active_hp, unit_vec)
        abs_cos = np.abs(cos_theta)

        # argpartition is O(N) vs argsort's O(N log N); order within the
        # partition doesn't matter — we only care which indices are smallest.
        bad_indices = np.argpartition(abs_cos, num_vec)[:num_vec]
        self.filtered_indices = bad_indices

        # Precompute the keep-mask once here so filtered_hamming_weights is
        # a single bitwise AND with no Python loop in the hot path.
        ignore_mask = 0
        for s in bad_indices:
            ignore_mask |= 1 << (self.num_bits - 1 - int(s))
        full_mask = (1 << self.num_bits) - 1
        self.clean_mask = (~ignore_mask) & full_mask

        return bad_indices

    def filtered_hamming_weights(self, intA: int, intB: int) -> int:
        if self.clean_mask is None:
            raise AssertionError("No existing Filtering")
        # Mask was precomputed in filter_by_hyperplane; just one AND + popcount.
        return bin((intA ^ intB) & self.clean_mask).count('1')

    def hamming_distance(self, a: int, b: int) -> int:
        return bin(a ^ b).count('1')