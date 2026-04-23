"""
precomp_scalarmult.py

Python wrapper around precomp_scalarmult.so.
Automatically selects w=4 or w=8 window based on expected_calls.

Usage:
    from precomp_scalarmult import PrecompPoint

    # Fixed bases used many times — w=8 selected automatically
    pt_G = PrecompPoint(G_bytes, expected_calls=10000)

    # Per-user base used few times — w=4 selected automatically
    pt_user = PrecompPoint(user_point, expected_calls=10)
"""

import ctypes
import pathlib

# ── Load shared libraries ─────────────────────────────────────────────
_HERE = pathlib.Path(__file__).parent

def _require(path: pathlib.Path) -> pathlib.Path:
    if not path.exists():
        raise FileNotFoundError(
            f"Shared library not found at {path}\n"
            "Run `bash build.sh` first to compile it."
        )
    return path

# Main library (used for batch_pedersen_commit, point_add_raw, etc.)
_lib = ctypes.CDLL(str(_require(_HERE / "_precomp_scalarmult.so")))

# Per-window libraries for PrecompPoint
_lib_w4 = ctypes.CDLL(str(_require(_HERE / "_precomp_scalarmult_w4.so")))
_lib_w8 = ctypes.CDLL(str(_require(_HERE / "_precomp_scalarmult_w8.so")))

# ── Constants ─────────────────────────────────────────────────────────
POINT_BYTES     = 32
SCALAR_BYTES    = 32
BREAKEVEN_CALLS = 240   # calls at which w=8 becomes cheaper than w=4

# ── Wire up main _lib ─────────────────────────────────────────────────
_lib.c_precomp_build.argtypes      = [ctypes.c_char_p]
_lib.c_precomp_build.restype       = ctypes.c_void_p
_lib.c_precomp_scalarmult.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.c_precomp_scalarmult.restype  = ctypes.c_int
_lib.c_precomp_free.argtypes       = [ctypes.c_void_p]
_lib.c_precomp_free.restype        = None
_lib.c_scalarmult_raw.argtypes     = [ctypes.c_char_p, ctypes.c_void_p]
_lib.c_scalarmult_raw.restype      = ctypes.c_void_p
_lib.c_point_add_raw.argtypes      = [ctypes.c_void_p, ctypes.c_void_p]
_lib.c_point_add_raw.restype       = ctypes.c_void_p
_lib.c_point_sub_raw.argtypes      = [ctypes.c_void_p, ctypes.c_void_p]
_lib.c_point_sub_raw.restype       = ctypes.c_void_p
_lib.c_encode_raw.argtypes         = [ctypes.c_char_p, ctypes.c_void_p]
_lib.c_encode_raw.restype          = ctypes.c_int
_lib.c_free_raw.argtypes           = [ctypes.c_void_p]
_lib.c_free_raw.restype            = None
_lib.c_free_batch.argtypes         = [ctypes.c_void_p]
_lib.c_free_batch.restype          = None
_lib.c_set_num_threads.argtypes    = [ctypes.c_int]
_lib.c_set_num_threads.restype     = None
_lib.c_get_num_threads.argtypes    = []
_lib.c_get_num_threads.restype     = ctypes.c_int
_lib.c_batch_scalarmult_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_int,
]
_lib.c_batch_scalarmult_raw.restype  = ctypes.c_int
_lib.c_batch_scalarmult_encode.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int,
]
_lib.c_batch_scalarmult_encode.restype  = ctypes.c_int
_lib.c_batch_pedersen_commit.argtypes = [
    ctypes.c_char_p,   # out
    ctypes.c_char_p,   # values
    ctypes.c_char_p,   # blinders
    ctypes.c_void_p,   # tbl_G
    ctypes.c_void_p,   # tbl_H
    ctypes.c_int,      # n
]
_lib.c_batch_pedersen_commit.restype  = ctypes.c_int
_lib.c_point_neg_raw.argtypes = [ctypes.c_void_p]
_lib.c_point_neg_raw.restype  = ctypes.c_void_p

_lib.c_batch_pedersen_commit_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out (n ge25519_p3*)
    ctypes.c_char_p,                  # values      (n × 32)
    ctypes.c_char_p,                  # blinders    (n × 32)
    ctypes.c_void_p,                  # tbl_G
    ctypes.c_void_p,                  # tbl_H
    ctypes.c_int,                     # n
]
_lib.c_batch_pedersen_commit_raw.restype = ctypes.c_int

# ── Wire up MSM on _lib ───────────────────────────────────────────────

_lib.c_multiscalar_mult_raw.argtypes = [
    ctypes.c_char_p,                 # scalars  (n × 32, packed)
    ctypes.POINTER(ctypes.c_void_p), # tables   (n PrecompTable*)
    ctypes.c_int,                    # n
]
_lib.c_multiscalar_mult_raw.restype = ctypes.c_void_p

_lib.c_multiscalar_mult_encode.argtypes = [
    ctypes.c_char_p,                 # out      (32 bytes)
    ctypes.c_char_p,                 # scalars  (n × 32, packed)
    ctypes.POINTER(ctypes.c_void_p), # tables   (n PrecompTable*)
    ctypes.c_int,                    # n
]
_lib.c_multiscalar_mult_encode.restype = ctypes.c_int

_lib.c_batch_multiscalar_mult_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), # results_out (batch_size ge25519_p3*)
    ctypes.c_char_p,                 # scalars  (batch_size × n × 32, packed)
    ctypes.POINTER(ctypes.c_void_p), # tables   (n PrecompTable*)
    ctypes.c_int,                    # n
    ctypes.c_int,                    # batch_size
]
_lib.c_batch_multiscalar_mult_raw.restype = ctypes.c_int

_lib.c_batch_multiscalar_mult_encode.argtypes = [
    ctypes.c_char_p,                 # out      (batch_size × 32)
    ctypes.c_char_p,                 # scalars  (batch_size × n × 32, packed)
    ctypes.POINTER(ctypes.c_void_p), # tables   (n PrecompTable*)
    ctypes.c_int,                    # n
    ctypes.c_int,                    # batch_size
]
_lib.c_batch_multiscalar_mult_encode.restype = ctypes.c_int

# in _lib bindings and inside _wire_window_lib:
_lib.c_scalarmult_point_raw.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
_lib.c_scalarmult_point_raw.restype  = ctypes.c_void_p

# ── Wire up short-scalar MSM on _lib ─────────────────────────────────
_lib.c_short_msm_raw.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
]
_lib.c_short_msm_raw.restype = ctypes.c_void_p

_lib.c_short_msm_encode.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_int, ctypes.c_int,
]
_lib.c_short_msm_encode.restype = ctypes.c_int

_lib.c_short_msm_zd_raw.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
]
_lib.c_short_msm_zd_raw.restype = ctypes.c_void_p

_lib.c_short_msm_zd_encode.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_int, ctypes.c_int,
]
_lib.c_short_msm_zd_encode.restype = ctypes.c_int

_lib.c_batch_short_msm_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out (batch_size ge25519_p3*)
    ctypes.c_char_p,                  # scalars  (batch_size × n × 32)
    ctypes.c_char_p,                  # points   (n × 32)
    ctypes.c_int,                     # n
    ctypes.c_int,                     # batch_size
    ctypes.c_int,                     # scalar_bits
]
_lib.c_batch_short_msm_raw.restype = ctypes.c_int

_lib.c_batch_short_msm_encode.argtypes = [
    ctypes.c_char_p,   # out      (batch_size × 32)
    ctypes.c_char_p,   # scalars  (batch_size × n × 32)
    ctypes.c_char_p,   # points   (n × 32)
    ctypes.c_int,      # n
    ctypes.c_int,      # batch_size
    ctypes.c_int,      # scalar_bits
]
_lib.c_batch_short_msm_encode.restype = ctypes.c_int

_lib.c_batch_short_msm_auto_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out
    ctypes.c_char_p,                  # scalars  (batch_size × n × 32)
    ctypes.c_char_p,                  # points   (n × 32)
    ctypes.c_int,                     # n
    ctypes.c_int,                     # batch_size
]
_lib.c_batch_short_msm_auto_raw.restype = ctypes.c_int

_lib.c_batch_short_msm_auto_encode.argtypes = [
    ctypes.c_char_p,   # out      (batch_size × 32)
    ctypes.c_char_p,   # scalars  (batch_size × n × 32)
    ctypes.c_char_p,   # points   (n × 32)
    ctypes.c_int,      # n
    ctypes.c_int,      # batch_size
]
_lib.c_batch_short_msm_auto_encode.restype = ctypes.c_int

_lib.c_batch_scalarmult_pairs_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out (n ge25519_p3*)
    ctypes.c_char_p,                  # scalars     (n × 32 bytes)
    ctypes.POINTER(ctypes.c_void_p),  # points      (n ge25519_p3*)
    ctypes.c_int,                     # n
]
_lib.c_batch_scalarmult_pairs_raw.restype = ctypes.c_int

_lib.c_batch_pow2_mult_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out (n ge25519_p3*)
    ctypes.POINTER(ctypes.c_void_p),  # points      (n ge25519_p3*)
    ctypes.c_int,                     # k  (number of doublings)
    ctypes.c_int,                     # n
]
_lib.c_batch_pow2_mult_raw.restype = ctypes.c_int

_lib.c_batch_offset_subtract_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # results_out (num_rows ge25519_p3*)
    ctypes.POINTER(ctypes.c_void_p),  # dot_pts     (num_rows ge25519_p3*)
    ctypes.c_char_p,                  # hvecs       (num_rows × num_cols int32, packed)
    ctypes.c_int64,                   # M
    ctypes.c_void_p,                  # tbl_G
    ctypes.c_int,                     # num_rows
    ctypes.c_int,                     # num_cols
]
_lib.c_batch_offset_subtract_raw.restype = ctypes.c_int

_lib.c_batch_offset_subtract_encode.argtypes = [
    ctypes.c_char_p,                  # out         (num_rows × 32)
    ctypes.POINTER(ctypes.c_void_p),  # dot_pts     (num_rows ge25519_p3*)
    ctypes.c_char_p,                  # hvecs       (num_rows × num_cols int32, packed)
    ctypes.c_int64,                   # M
    ctypes.c_void_p,                  # tbl_G
    ctypes.c_int,                     # num_rows
    ctypes.c_int,                     # num_cols
]
_lib.c_batch_offset_subtract_encode.restype = ctypes.c_int

_lib.c_batch_nizk_hash_prove.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # a_c_pts   (n ge25519_p3*)
    ctypes.POINTER(ctypes.c_void_p),  # a_r_pts   (n ge25519_p3*)
    ctypes.POINTER(ctypes.c_void_p),  # r_pts     (n ge25519_p3*)
    ctypes.c_char_p,                  # C_bytes   (n × 32)
    ctypes.c_char_p,                  # G_bytes   (32)
    ctypes.c_char_p,                  # H_bytes   (32)
    ctypes.c_char_p,                  # kx_packed (n × 32)
    ctypes.c_char_p,                  # kr_packed (n × 32)
    ctypes.c_char_p,                  # x_packed  (n × 32)
    ctypes.c_char_p,                  # r_packed  (n × 32)
    ctypes.c_char_p,                  # proofs_out (n × 96, caller-allocated)
    ctypes.c_int,                     # n
]
_lib.c_batch_nizk_hash_prove.restype = ctypes.c_int

_lib.c_batch_hash_enc.argtypes = [
    ctypes.c_char_p,  # prf_bytes   (n × 32)
    ctypes.c_char_p,  # payload     (32)
    ctypes.c_char_p,  # tags_out    (n × 32)
    ctypes.c_char_p,  # ciphers_out (n × 48)
    ctypes.c_int,     # n
]
_lib.c_batch_hash_enc.restype = ctypes.c_int

_lib.c_batch_sha256_tag_key.argtypes = [
    ctypes.c_char_p,  # prf_bytes  (n × 32)
    ctypes.c_char_p,  # tags_out   (n × 32)
    ctypes.c_char_p,  # keys_out   (n × 32)
    ctypes.c_int,     # n
]
_lib.c_batch_sha256_tag_key.restype = ctypes.c_int

_lib.c_batch_secretbox_open_verify.argtypes = [
    ctypes.c_char_p,  # keys             (n × 32)
    ctypes.c_char_p,  # ciphers          (n × 48)
    ctypes.c_char_p,  # expected_payload (32)
    ctypes.c_int,     # n
]
_lib.c_batch_secretbox_open_verify.restype = ctypes.c_int

_lib.c_batch_nizk_hash_verify.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # a_hat_c   (n ge25519_p3*)
    ctypes.POINTER(ctypes.c_void_p),  # a_hat_r   (n ge25519_p3*)
    ctypes.c_char_p,                  # C_bytes   (n × 32)
    ctypes.c_char_p,                  # R_bytes   (n × 32)
    ctypes.c_char_p,                  # G_bytes   (32)
    ctypes.c_char_p,                  # H_bytes   (32)
    ctypes.c_char_p,                  # e_expected (32) — single challenge
    ctypes.c_int,                     # n
]
_lib.c_batch_nizk_hash_verify.restype = ctypes.c_int

# ── Wire up per-window libs ───────────────────────────────────────────
def _wire_window_lib(lib):
    lib.c_precomp_build.argtypes         = [ctypes.c_char_p]
    lib.c_precomp_build.restype          = ctypes.c_void_p
    lib.c_precomp_scalarmult.argtypes    = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
    lib.c_precomp_scalarmult.restype     = ctypes.c_int
    lib.c_precomp_free.argtypes          = [ctypes.c_void_p]
    lib.c_precomp_free.restype           = None
    lib.c_scalarmult_raw.argtypes        = [ctypes.c_char_p, ctypes.c_void_p]
    lib.c_scalarmult_raw.restype         = ctypes.c_void_p
    lib.c_encode_raw.argtypes            = [ctypes.c_char_p, ctypes.c_void_p]
    lib.c_encode_raw.restype             = ctypes.c_int
    lib.c_free_raw.argtypes              = [ctypes.c_void_p]
    lib.c_free_raw.restype               = None
    lib.c_free_batch.argtypes            = [ctypes.c_void_p]
    lib.c_free_batch.restype             = None
    lib.c_point_add_raw.argtypes         = [ctypes.c_void_p, ctypes.c_void_p]
    lib.c_point_add_raw.restype          = ctypes.c_void_p
    lib.c_set_num_threads.argtypes       = [ctypes.c_int]
    lib.c_set_num_threads.restype        = None
    lib.c_get_num_threads.argtypes       = []
    lib.c_get_num_threads.restype        = ctypes.c_int
    lib.c_batch_scalarmult_raw.argtypes  = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    lib.c_batch_scalarmult_raw.restype   = ctypes.c_int
    lib.c_batch_scalarmult_encode.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int,
    ]
    lib.c_batch_scalarmult_encode.restype  = ctypes.c_int
    lib.c_point_neg_raw.argtypes = [ctypes.c_void_p]
    lib.c_point_neg_raw.restype  = ctypes.c_void_p

    lib.c_multiscalar_mult_raw.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
    ]
    lib.c_multiscalar_mult_raw.restype = ctypes.c_void_p

    lib.c_multiscalar_mult_encode.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
    ]
    lib.c_multiscalar_mult_encode.restype = ctypes.c_int

    lib.c_batch_multiscalar_mult_raw.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
        ctypes.c_int,
    ]
    lib.c_batch_multiscalar_mult_raw.restype = ctypes.c_int

    lib.c_batch_multiscalar_mult_encode.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
        ctypes.c_int,
    ]
    lib.c_batch_multiscalar_mult_encode.restype = ctypes.c_int
    lib.c_batch_pedersen_commit_raw.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_int,
    ]
    lib.c_batch_pedersen_commit_raw.restype = ctypes.c_int
    
    lib.c_scalarmult_point_raw.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.c_scalarmult_point_raw.restype  = ctypes.c_void_p

    lib.c_short_msm_raw.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
    ]
    lib.c_short_msm_raw.restype = ctypes.c_void_p

    lib.c_short_msm_encode.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int,
    ]
    lib.c_short_msm_encode.restype = ctypes.c_int

    lib.c_short_msm_zd_raw.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
    ]
    lib.c_short_msm_zd_raw.restype = ctypes.c_void_p

    lib.c_short_msm_zd_encode.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int,
    ]
    lib.c_short_msm_zd_encode.restype = ctypes.c_int

    lib.c_batch_short_msm_raw.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
    ]
    lib.c_batch_short_msm_raw.restype = ctypes.c_int

    lib.c_batch_short_msm_encode.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
    ]
    lib.c_batch_short_msm_encode.restype = ctypes.c_int

    lib.c_batch_short_msm_auto_raw.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int,
    ]
    lib.c_batch_short_msm_auto_raw.restype = ctypes.c_int

    lib.c_batch_short_msm_auto_encode.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int,
    ]
    lib.c_batch_short_msm_auto_encode.restype = ctypes.c_int

    lib.c_batch_offset_subtract_raw.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),  # results_out
        ctypes.POINTER(ctypes.c_void_p),  # dot_pts
        ctypes.c_char_p,                  # hvecs
        ctypes.c_int64,                   # M
        ctypes.c_void_p,                  # tbl_G
        ctypes.c_int,                     # num_rows
        ctypes.c_int,                     # num_cols
    ]
    lib.c_batch_offset_subtract_raw.restype = ctypes.c_int

    lib.c_batch_offset_subtract_encode.argtypes = [
        ctypes.c_char_p,                  # out
        ctypes.POINTER(ctypes.c_void_p),  # dot_pts
        ctypes.c_char_p,                  # hvecs
        ctypes.c_int64,                   # M
        ctypes.c_void_p,                  # tbl_G
        ctypes.c_int,                     # num_rows
        ctypes.c_int,                     # num_cols
    ]
    lib.c_batch_offset_subtract_encode.restype = ctypes.c_int

_wire_window_lib(_lib_w4)
_wire_window_lib(_lib_w8)

# ── RawPoint ──────────────────────────────────────────────────────────

class RawPoint:
    """
    A ristretto255 point in raw extended Edwards form.
    No encoding/decoding until you explicitly call .encode().
    """

    def __init__(self, ptr: int, batch_block=None, lib=None):
        if ptr is None or ptr == 0:
            raise RuntimeError("Null raw point — scalarmult failed")
        self._ptr         = ptr
        self._batch_block = batch_block
        self._lib         = lib if lib is not None else _lib

    def encode(self) -> bytes:
        """Encode to 32-byte ristretto255 — call once at end of protocol."""
        out = ctypes.create_string_buffer(POINT_BYTES)
        self._lib.c_encode_raw(out, self._ptr)
        return bytes(out)

    def __add__(self, other: "RawPoint") -> "RawPoint":
        """Add two raw points — stays in Edwards form, no encode."""
        ptr = self._lib.c_point_add_raw(self._ptr, other._ptr)
        return RawPoint(ptr, lib=self._lib)
    
    # Inside RawPoint, alongside __add__:
    def __neg__(self) -> "RawPoint":
        """Negate this raw point — stays in Edwards form, no encode."""
        ptr = self._lib.c_point_neg_raw(self._ptr)
        return RawPoint(ptr, lib=self._lib)

    def __sub__(self, other: "RawPoint") -> "RawPoint":
        """Subtract two raw points via negation — stays in Edwards form."""
        return self.__add__(other.__neg__())

    def __del__(self):
        if hasattr(self, "_ptr") and self._ptr:
            if self._batch_block is None:
                self._lib.c_free_raw(self._ptr)
            self._ptr = 0


# ── PrecompPoint ──────────────────────────────────────────────────────

class PrecompPoint:
    """
    A ristretto255 point with a precomputed windowed table.

    Automatically selects window size based on expected_calls:
      < BREAKEVEN_CALLS  → w=4  (fast build ~170µs, moderate per-call)
      >= BREAKEVEN_CALLS → w=8  (slow build ~950µs, fast per-call)
    """

    def __init__(self, point_bytes: bytes, expected_calls: int = 100):
        """
        Parameters
        ----------
        point_bytes    : 32-byte ristretto255-encoded point
        expected_calls : hint for window size selection (default 100 → w=4)
        """
        if len(point_bytes) != POINT_BYTES:
            raise ValueError(f"point_bytes must be {POINT_BYTES} bytes")

        if expected_calls >= BREAKEVEN_CALLS:
            self._lib    = _lib_w8
            self._window = 8
        else:
            self._lib    = _lib_w4
            self._window = 4

        self._tbl = self._lib.c_precomp_build(point_bytes)
        if self._tbl is None:
            raise ValueError("Invalid ristretto255 point — decoding failed")

    def scalarmult(self, scalar: bytes) -> bytes:
        """Multiply this point by scalar, return 32-byte encoded result."""
        if len(scalar) != SCALAR_BYTES:
            raise ValueError(f"scalar must be {SCALAR_BYTES} bytes")
        out = ctypes.create_string_buffer(POINT_BYTES)
        self._lib.c_precomp_scalarmult(out, scalar, self._tbl)
        return bytes(out)

    def scalarmult_raw(self, scalar: bytes) -> RawPoint:
        """Multiply and return raw Edwards point — no encode."""
        if len(scalar) != SCALAR_BYTES:
            raise ValueError(f"scalar must be {SCALAR_BYTES} bytes")
        ptr = self._lib.c_scalarmult_raw(scalar, self._tbl)
        return RawPoint(ptr, lib=self._lib)

    def scalarmult_raw_batch(self, scalars: list) -> list:
        """Batch multiply — single C call, returns list of RawPoint."""
        n         = len(scalars)
        if n == 0:
            return []
        packed    = b"".join(scalars)
        PtrArray  = ctypes.c_void_p * n
        ptrs      = PtrArray()
        self._lib.c_batch_scalarmult_raw(ptrs, packed, self._tbl, ctypes.c_int(n))
        block_ref = ctypes.c_void_p(ptrs[0])
        return [RawPoint(ptrs[k], batch_block=block_ref, lib=self._lib) for k in range(n)]

    def scalarmult_batch_encoded(self, scalars: list) -> list:
        """Batch multiply returning encoded bytes — stays entirely in C."""
        n      = len(scalars)
        if n == 0:
            return []
        packed = b"".join(scalars)
        out    = ctypes.create_string_buffer(n * POINT_BYTES)
        ret    = self._lib.c_batch_scalarmult_encode(out, packed, self._tbl, ctypes.c_int(n))
        if ret != 0:
            raise RuntimeError("batch_scalarmult_encode failed")
        return [bytes(out[k * POINT_BYTES:(k+1) * POINT_BYTES]) for k in range(n)]

    def __del__(self):
        if hasattr(self, "_tbl") and self._tbl is not None:
            self._lib.c_precomp_free(self._tbl)
            self._tbl = None


# ── Module-level functions ────────────────────────────────────────────

def point_add_raw(a: RawPoint, b: RawPoint) -> RawPoint:
    """Add two raw Edwards points — no encode/decode."""
    ptr = a._lib.c_point_add_raw(a._ptr, b._ptr)
    return RawPoint(ptr, lib=a._lib)

def point_sub_raw(a: RawPoint, b: RawPoint) -> RawPoint:
    """Subtract two raw Edwards points via negation + addition."""
    return a + (-b)

# Module-level, alongside point_add_raw / point_sub_raw:
def point_neg_raw(p: RawPoint) -> RawPoint:
    """Negate a raw Edwards point — no encode/decode."""
    ptr = p._lib.c_point_neg_raw(p._ptr)
    return RawPoint(ptr, lib=p._lib)

def batch_pedersen_commit(pt_G: PrecompPoint,
                           pt_H: PrecompPoint,
                           values: list,
                           blinders: list) -> list:
    """
    Compute n Pedersen commitments C_k = v_k*G + r_k*H in one C call.
    Uses OpenMP parallelism. Returns list of 32-byte encoded points.
    """
    n = len(values)
    if n != len(blinders):
        raise ValueError("values and blinders must have the same length")
    if n == 0:
        return []
    packed_v = b"".join(values)
    packed_r = b"".join(blinders)
    out      = ctypes.create_string_buffer(n * POINT_BYTES)
    ret = _lib.c_batch_pedersen_commit(
        out, packed_v, packed_r,
        pt_G._tbl, pt_H._tbl,
        ctypes.c_int(n)
    )
    if ret != 0:
        raise RuntimeError("batch_pedersen_commit failed")
    return [bytes(out[k * POINT_BYTES:(k+1) * POINT_BYTES]) for k in range(n)]


def batch_scalarmult_raw(pt: PrecompPoint, scalars: list) -> list:
    """Convenience wrapper for pt.scalarmult_raw_batch(scalars)."""
    return pt.scalarmult_raw_batch(scalars)


def set_num_threads(n: int):
    """Set OpenMP thread count for all batch operations."""
    _lib.c_set_num_threads(ctypes.c_int(n))
    _lib_w4.c_set_num_threads(ctypes.c_int(n))
    _lib_w8.c_set_num_threads(ctypes.c_int(n))


def get_num_threads() -> int:
    """Return current OpenMP thread count."""
    return _lib.c_get_num_threads()

def batch_pedersen_commit(pt_G: PrecompPoint,
                           pt_H: PrecompPoint,
                           values: list,
                           blinders: list) -> list:
    n = len(values)
    if n != len(blinders):
        raise ValueError("values and blinders must have the same length")
    if n == 0:
        return []

    # Use pt_G's lib — must match the lib that built the tables
    lib = pt_G._lib

    # Wire up c_batch_pedersen_commit on this specific lib if not already done
    lib.c_batch_pedersen_commit.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
    ]
    lib.c_batch_pedersen_commit.restype = ctypes.c_int

    packed_v = b"".join(values)
    packed_r = b"".join(blinders)
    out      = ctypes.create_string_buffer(n * POINT_BYTES)

    ret = lib.c_batch_pedersen_commit(
        out, packed_v, packed_r,
        pt_G._tbl, pt_H._tbl,
        ctypes.c_int(n)
    )
    if ret != 0:
        raise RuntimeError("batch_pedersen_commit failed")

    return [bytes(out[k * POINT_BYTES:(k+1) * POINT_BYTES]) for k in range(n)]

def _pack_table_ptrs(points: list):
    """Build a ctypes c_void_p array of the PrecompTable pointers."""
    n = len(points)
    arr = (ctypes.c_void_p * n)(*(pt._tbl for pt in points))
    return arr


def _pack_scalars_flat(scalars_batch, n: int) -> bytes:
    """
    Pack a list-of-lists of scalars into a flat bytes object.

    scalars_batch[m][k] is the scalar for MSM item m, base k.
    Output layout: batch_size × n × SCALAR_BYTES, batch-major.
    """
    parts = []
    for row in scalars_batch:
        if len(row) != n:
            raise ValueError(
                f"Each scalar row must have {n} entries (one per base point); "
                f"got {len(row)}"
            )
        parts.extend(row)
    return b"".join(parts)

def multiscalar_mult_raw(points: list, scalars: list) -> RawPoint:
    n = len(points)
    if len(scalars) != n:
        raise ValueError(f"scalars length {len(scalars)} != points length {n}")
    lib      = points[0]._lib
    packed_s = b"".join(scalars)
    tbl_arr  = _pack_table_ptrs(points)
    ptr = lib.c_multiscalar_mult_raw(packed_s, tbl_arr, ctypes.c_int(n))
    return RawPoint(ptr, lib=lib)


def multiscalar_mult(points: list, scalars: list) -> bytes:
    n = len(points)
    if len(scalars) != n:
        raise ValueError(f"scalars length {len(scalars)} != points length {n}")
    lib      = points[0]._lib
    packed_s = b"".join(scalars)
    tbl_arr  = _pack_table_ptrs(points)
    out      = ctypes.create_string_buffer(POINT_BYTES)
    ret = lib.c_multiscalar_mult_encode(out, packed_s, tbl_arr, ctypes.c_int(n))
    if ret != 0:
        raise RuntimeError("multiscalar_mult_encode failed")
    return bytes(out)


def batch_multiscalar_mult_raw(points: list, scalars_batch: list) -> list:
    n          = len(points)
    batch_size = len(scalars_batch)
    if n == 0 or batch_size == 0:
        return []
    lib      = points[0]._lib
    packed   = _pack_scalars_flat(scalars_batch, n)
    tbl_arr  = _pack_table_ptrs(points)
    PtrArray = ctypes.c_void_p * batch_size
    ptrs     = PtrArray()
    ret = lib.c_batch_multiscalar_mult_raw(
        ptrs, packed, tbl_arr,
        ctypes.c_int(n), ctypes.c_int(batch_size),
    )
    if ret != 0:
        raise RuntimeError("batch_multiscalar_mult_raw failed")
    block_ref = ctypes.c_void_p(ptrs[0])
    return [RawPoint(ptrs[m], batch_block=block_ref, lib=lib) for m in range(batch_size)]


def batch_multiscalar_mult(points: list, scalars_batch: list) -> list:
    n          = len(points)
    batch_size = len(scalars_batch)
    if n == 0 or batch_size == 0:
        return []
    lib     = points[0]._lib
    packed  = _pack_scalars_flat(scalars_batch, n)
    tbl_arr = _pack_table_ptrs(points)
    out     = ctypes.create_string_buffer(batch_size * POINT_BYTES)
    ret = lib.c_batch_multiscalar_mult_encode(
        out, packed, tbl_arr,
        ctypes.c_int(n), ctypes.c_int(batch_size),
    )
    if ret != 0:
        raise RuntimeError("batch_multiscalar_mult_encode failed")
    return [bytes(out[m * POINT_BYTES:(m + 1) * POINT_BYTES]) for m in range(batch_size)]

def batch_pedersen_commit_raw(pt_G: PrecompPoint,
                               pt_H: PrecompPoint,
                               values: list,
                               blinders: list) -> list:
    """
    Compute n Pedersen commitments C_k = v_k*G + r_k*H, returning raw RawPoints.

    Parameters
    ----------
    pt_G      : PrecompPoint for the value base G
    pt_H      : PrecompPoint for the blinding base H
    values    : list of n 32-byte little-endian value scalars
    blinders  : list of n 32-byte little-endian blinding scalars

    Returns
    -------
    list of n RawPoint — all share one contiguous allocation,
    freed when results[0] is garbage-collected (batch_block mechanism).
    """
    n = len(values)
    if n != len(blinders):
        raise ValueError("values and blinders must have the same length")
    if n == 0:
        return []

    lib      = pt_G._lib
    packed_v = b"".join(values)
    packed_r = b"".join(blinders)

    PtrArray = ctypes.c_void_p * n
    ptrs     = PtrArray()

    ret = lib.c_batch_pedersen_commit_raw(
        ptrs, packed_v, packed_r,
        pt_G._tbl, pt_H._tbl,
        ctypes.c_int(n),
    )
    if ret != 0:
        raise RuntimeError("batch_pedersen_commit_raw failed (allocation error in C)")

    block_ref = ctypes.c_void_p(ptrs[0])
    return [RawPoint(ptrs[k], batch_block=block_ref, lib=lib) for k in range(n)]

def scalarmult_rawpoint(scalar: bytes, point: RawPoint) -> RawPoint:
    """
    Compute scalar * point for a one-shot arbitrary RawPoint.
    No precomputed table built — strictly cheaper than PrecompPoint for single use.

    Parameters
    ----------
    scalar : 32-byte little-endian scalar
    point  : RawPoint in raw Edwards form

    Returns
    -------
    RawPoint — caller owns it via normal GC / __del__
    """
    if len(scalar) != SCALAR_BYTES:
        raise ValueError(f"scalar must be {SCALAR_BYTES} bytes")
    ptr = point._lib.c_scalarmult_point_raw(scalar, point._ptr)
    if ptr is None or ptr == 0:
        raise RuntimeError("c_scalarmult_point_raw failed — invalid point or scalar")
    return RawPoint(ptr, lib=point._lib)

def decode_to_raw(point_bytes: bytes) -> RawPoint:
    """Decode a 32-byte ristretto255 point into a RawPoint."""
    if len(point_bytes) != POINT_BYTES:
        raise ValueError(f"point_bytes must be {POINT_BYTES} bytes")
    # scalarmult by 1 — decodes and returns the point unchanged
    buf = ctypes.create_string_buffer(b"\x01" + b"\x00" * 31)
    tmp = _lib_w4.c_precomp_build(point_bytes)
    if tmp is None:
        raise ValueError("Invalid ristretto255 point")
    ptr = _lib_w4.c_scalarmult_raw(buf, tmp)
    _lib_w4.c_precomp_free(tmp)
    return RawPoint(ptr, lib=_lib_w4)


# ── Short-scalar MSM (subset-sum tables) ─────────────────────────────

def short_msm_raw(scalars: list, points: list, scalar_bits: int) -> RawPoint:
    """
    Compute sum(s_k * P_k) using subset-sum tables + double-and-add.

    Parameters
    ----------
    scalars     : list of n 32-byte little-endian scalars
    points      : list of n 32-byte ristretto255-encoded points
    scalar_bits : effective bit-length of the scalars

    Returns
    -------
    RawPoint in raw Edwards form.
    """
    n = len(scalars)
    if len(points) != n:
        raise ValueError(f"scalars length {n} != points length {len(points)}")
    if n == 0:
        raise ValueError("empty input")
    packed_s = b"".join(scalars)
    packed_p = b"".join(bytes(p) for p in points)
    ptr = _lib.c_short_msm_raw(packed_s, packed_p,
                                ctypes.c_int(n), ctypes.c_int(scalar_bits))
    if ptr is None or ptr == 0:
        raise RuntimeError("c_short_msm_raw failed")
    return RawPoint(ptr, lib=_lib)


def short_msm(scalars: list, points: list, scalar_bits: int) -> bytes:
    """
    Compute sum(s_k * P_k) using subset-sum tables + double-and-add.
    Returns 32-byte ristretto255-encoded result.
    """
    n = len(scalars)
    if len(points) != n:
        raise ValueError(f"scalars length {n} != points length {len(points)}")
    if n == 0:
        raise ValueError("empty input")
    packed_s = b"".join(scalars)
    packed_p = b"".join(bytes(p) for p in points)
    out = ctypes.create_string_buffer(POINT_BYTES)
    ret = _lib.c_short_msm_encode(out, packed_s, packed_p,
                                   ctypes.c_int(n), ctypes.c_int(scalar_bits))
    if ret != 0:
        raise RuntimeError("c_short_msm_encode failed")
    return bytes(out)


def short_msm_zd_raw(scalars: list, points: list, scalar_bits: int) -> RawPoint:
    """
    Compute sum(s_k * P_k) using subset-sum tables + zero-doubling.

    Precomputes scalar_bits levels of tables (each level doubled from previous).
    Evaluation is additions only — zero doublings.  Uses more memory than
    short_msm_raw but the eval loop is faster for very short scalars.

    Parameters
    ----------
    scalars     : list of n 32-byte little-endian scalars
    points      : list of n 32-byte ristretto255-encoded points
    scalar_bits : effective bit-length of the scalars

    Returns
    -------
    RawPoint in raw Edwards form.
    """
    n = len(scalars)
    if len(points) != n:
        raise ValueError(f"scalars length {n} != points length {len(points)}")
    if n == 0:
        raise ValueError("empty input")
    packed_s = b"".join(scalars)
    packed_p = b"".join(bytes(p) for p in points)
    ptr = _lib.c_short_msm_zd_raw(packed_s, packed_p,
                                    ctypes.c_int(n), ctypes.c_int(scalar_bits))
    if ptr is None or ptr == 0:
        raise RuntimeError("c_short_msm_zd_raw failed")
    return RawPoint(ptr, lib=_lib)


def short_msm_zd(scalars: list, points: list, scalar_bits: int) -> bytes:
    """
    Compute sum(s_k * P_k) using subset-sum tables + zero-doubling.
    Returns 32-byte ristretto255-encoded result.
    """
    n = len(scalars)
    if len(points) != n:
        raise ValueError(f"scalars length {n} != points length {len(points)}")
    if n == 0:
        raise ValueError("empty input")
    packed_s = b"".join(scalars)
    packed_p = b"".join(bytes(p) for p in points)
    out = ctypes.create_string_buffer(POINT_BYTES)
    ret = _lib.c_short_msm_zd_encode(out, packed_s, packed_p,
                                      ctypes.c_int(n), ctypes.c_int(scalar_bits))
    if ret != 0:
        raise RuntimeError("c_short_msm_zd_encode failed")
    return bytes(out)


def batch_short_msm_raw(scalars_batch: list,
                         points: list,
                         scalar_bits: int) -> list:
    """
    Compute batch_size independent MSMs in parallel:
        result_m = sum_k scalar_batch[m][k] * points[k]

    The base points are shared across all MSMs — the subset-sum tables
    are built once and reused, so this is much faster than calling
    short_msm_raw in a loop.

    Parameters
    ----------
    scalars_batch : list of batch_size lists, each containing n 32-byte scalars
                    (batch-major: scalars_batch[m][k] for MSM m, point k)
    points        : list of n 32-byte ristretto255-encoded base points
    scalar_bits   : effective bit-length of the scalars

    Returns
    -------
    list of batch_size RawPoints — all share one contiguous allocation,
    freed when results[0] is garbage-collected (batch_block mechanism).
    """
    batch_size = len(scalars_batch)
    n = len(points)
    if batch_size == 0 or n == 0:
        raise ValueError("empty input")
    for m, row in enumerate(scalars_batch):
        if len(row) != n:
            raise ValueError(
                f"scalars_batch[{m}] has {len(row)} entries, expected {n}"
            )

    packed_s = b"".join(s for row in scalars_batch for s in row)
    packed_p = b"".join(bytes(p) for p in points)

    PtrArray = ctypes.c_void_p * batch_size
    ptrs     = PtrArray()

    ret = _lib.c_batch_short_msm_raw(
        ptrs, packed_s, packed_p,
        ctypes.c_int(n), ctypes.c_int(batch_size), ctypes.c_int(scalar_bits),
    )
    if ret != 0:
        raise RuntimeError("c_batch_short_msm_raw failed")

    block_ref = ctypes.c_void_p(ptrs[0])
    return [RawPoint(ptrs[m], batch_block=block_ref, lib=_lib)
            for m in range(batch_size)]


def batch_short_msm_auto_raw(scalars_batch: list,
                              points: list) -> list:
    """
    Like batch_short_msm_raw but with no scalar_bits parameter.

    Scans all scalars after reduction to find the highest set bit and
    iterates exactly that many positions — padded zero bytes cost nothing.
    Ideal when scalar magnitudes vary or are not known in advance.

    Parameters
    ----------
    scalars_batch : list of batch_size lists, each containing n 32-byte scalars
    points        : list of n 32-byte ristretto255-encoded base points

    Returns
    -------
    list of batch_size RawPoints sharing one contiguous allocation.
    """
    batch_size = len(scalars_batch)
    n = len(points)
    if batch_size == 0 or n == 0:
        raise ValueError("empty input")
    for m, row in enumerate(scalars_batch):
        if len(row) != n:
            raise ValueError(
                f"scalars_batch[{m}] has {len(row)} entries, expected {n}"
            )
    packed_s = b"".join(s for row in scalars_batch for s in row)
    packed_p = b"".join(bytes(p) for p in points)
    PtrArray = ctypes.c_void_p * batch_size
    ptrs     = PtrArray()
    ret = _lib.c_batch_short_msm_auto_raw(
        ptrs, packed_s, packed_p,
        ctypes.c_int(n), ctypes.c_int(batch_size),
    )
    if ret != 0:
        raise RuntimeError("c_batch_short_msm_auto_raw failed")
    block_ref = ctypes.c_void_p(ptrs[0])
    return [RawPoint(ptrs[m], batch_block=block_ref, lib=_lib)
            for m in range(batch_size)]


def batch_short_msm_auto(scalars_batch: list,
                          points: list) -> list:
    """
    Like batch_short_msm but with no scalar_bits parameter.
    Auto-detects the effective bit length from the scalar values.
    Returns list of batch_size encoded 32-byte results.
    """
    batch_size = len(scalars_batch)
    n = len(points)
    if batch_size == 0 or n == 0:
        raise ValueError("empty input")
    for m, row in enumerate(scalars_batch):
        if len(row) != n:
            raise ValueError(
                f"scalars_batch[{m}] has {len(row)} entries, expected {n}"
            )
    packed_s = b"".join(s for row in scalars_batch for s in row)
    packed_p = b"".join(bytes(p) for p in points)
    out = ctypes.create_string_buffer(batch_size * POINT_BYTES)
    ret = _lib.c_batch_short_msm_auto_encode(
        out, packed_s, packed_p,
        ctypes.c_int(n), ctypes.c_int(batch_size),
    )
    if ret != 0:
        raise RuntimeError("c_batch_short_msm_auto_encode failed")
    return [bytes(out[m * POINT_BYTES:(m + 1) * POINT_BYTES])
            for m in range(batch_size)]


def batch_short_msm(scalars_batch: list,
                     points: list,
                     scalar_bits: int) -> list:
    """
    Like batch_short_msm_raw but encodes each result to 32-byte
    ristretto255 bytes entirely in C — no RawPoint objects allocated.

    Returns list of batch_size bytes objects.
    """
    batch_size = len(scalars_batch)
    n = len(points)
    if batch_size == 0 or n == 0:
        raise ValueError("empty input")
    for m, row in enumerate(scalars_batch):
        if len(row) != n:
            raise ValueError(
                f"scalars_batch[{m}] has {len(row)} entries, expected {n}"
            )

    packed_s = b"".join(s for row in scalars_batch for s in row)
    packed_p = b"".join(bytes(p) for p in points)
    out = ctypes.create_string_buffer(batch_size * POINT_BYTES)

    ret = _lib.c_batch_short_msm_encode(
        out, packed_s, packed_p,
        ctypes.c_int(n), ctypes.c_int(batch_size), ctypes.c_int(scalar_bits),
    )
    if ret != 0:
        raise RuntimeError("c_batch_short_msm_encode failed")

    return [bytes(out[m * POINT_BYTES:(m + 1) * POINT_BYTES])
            for m in range(batch_size)]

def batch_offset_subtract_raw(dot_points: list,
                               hypervectors,
                               M: int,
                               pt_G: "PrecompPoint") -> list:
    """
    For each row i:
        sum_h         = sum(hypervectors[i])
        offset_scalar = (M * sum_h) mod L
        offset_point  = offset_scalar * G
        result[i]     = dot_points[i] - offset_point

    Equivalent to the Python loop in CreateDotCommitment but fully in C
    with OpenMP parallelism across rows.

    Parameters
    ----------
    dot_points   : list of num_rows RawPoints  (from batch_multiscalar_mult_raw)
    hypervectors : 2-D array-like of int32, shape (num_rows, num_cols)
    M            : integer multiplier (e.g. 2047)
    pt_G         : PrecompPoint for the base point G

    Returns
    -------
    list of num_rows RawPoints sharing one contiguous allocation.
    Free with the normal RawPoint GC (batch_block mechanism).
    """
    import numpy as np

    num_rows = len(dot_points)
    hvecs    = np.asarray(hypervectors, dtype=np.int32)
    if hvecs.ndim != 2 or hvecs.shape[0] != num_rows:
        raise ValueError("hypervectors must be 2-D with first dim == len(dot_points)")
    num_cols = hvecs.shape[1]

    # Pack dot_points pointers into a C array
    DotPtrArray = ctypes.c_void_p * num_rows
    dot_ptrs    = DotPtrArray(*(p._ptr for p in dot_points))

    # Output pointer array
    PtrArray    = ctypes.c_void_p * num_rows
    out_ptrs    = PtrArray()

    lib = pt_G._lib
    ret = lib.c_batch_offset_subtract_raw(
        out_ptrs,
        dot_ptrs,
        hvecs.tobytes(),
        ctypes.c_int64(M),
        pt_G._tbl,
        ctypes.c_int(num_rows),
        ctypes.c_int(num_cols),
    )
    if ret != 0:
        raise RuntimeError("c_batch_offset_subtract_raw failed")

    block_ref = ctypes.c_void_p(out_ptrs[0])
    return [RawPoint(out_ptrs[i], batch_block=block_ref, lib=lib)
            for i in range(num_rows)]


def batch_offset_subtract(dot_points: list,
                           hypervectors,
                           M: int,
                           pt_G: "PrecompPoint") -> list:
    """
    Like batch_offset_subtract_raw but encodes each result to 32-byte
    ristretto255 bytes entirely in C — no RawPoint objects allocated.

    Returns list of num_rows bytes objects.
    """
    import numpy as np

    num_rows = len(dot_points)
    hvecs    = np.asarray(hypervectors, dtype=np.int32)
    if hvecs.ndim != 2 or hvecs.shape[0] != num_rows:
        raise ValueError("hypervectors must be 2-D with first dim == len(dot_points)")
    num_cols = hvecs.shape[1]

    DotPtrArray = ctypes.c_void_p * num_rows
    dot_ptrs    = DotPtrArray(*(p._ptr for p in dot_points))

    out = ctypes.create_string_buffer(num_rows * POINT_BYTES)

    ret = pt_G._lib.c_batch_offset_subtract_encode(
        out,
        dot_ptrs,
        hvecs.tobytes(),
        ctypes.c_int64(M),
        pt_G._tbl,
        ctypes.c_int(num_rows),
        ctypes.c_int(num_cols),
    )
    if ret != 0:
        raise RuntimeError("c_batch_offset_subtract_encode failed")

    return [bytes(out[i * POINT_BYTES:(i + 1) * POINT_BYTES])
            for i in range(num_rows)]


def batch_pow2_mult_raw(points: list, k: int) -> list:
    """
    For each point P in points, compute 2^k * P using k successive doublings.

    Much faster than scalarmult_rawpoint(int_to_scalar_bytes(1 << k), P)
    when the scalar is a power of two — uses k doublings instead of a full
    252-bit variable-base scalar multiplication.

    Parameters
    ----------
    points : list of n RawPoints
    k      : number of doublings (scalar = 2^k)

    Returns
    -------
    list of n RawPoints sharing one contiguous allocation.
    """
    n = len(points)
    if n == 0:
        raise ValueError("empty input")

    PtrArray  = ctypes.c_void_p * n
    in_ptrs   = PtrArray(*(p._ptr for p in points))
    out_ptrs  = PtrArray()

    ret = _lib.c_batch_pow2_mult_raw(
        out_ptrs, in_ptrs, ctypes.c_int(k), ctypes.c_int(n),
    )
    if ret != 0:
        raise RuntimeError("c_batch_pow2_mult_raw failed")

    block_ref = ctypes.c_void_p(out_ptrs[0])
    return [RawPoint(out_ptrs[i], batch_block=block_ref, lib=_lib)
            for i in range(n)]


def batch_scalarmult_pairs_raw(scalars: list, points: list) -> list:
    """
    Compute result[i] = scalar[i] * point[i] for all i, in parallel.
    Both scalars and points vary per element — full 252-bit scalar mult.

    Much faster than N sequential scalarmult_rawpoint calls when N is large,
    because all N multiplications run concurrently across OpenMP threads.

    Parameters
    ----------
    scalars : list of n 32-byte scalars
    points  : list of n RawPoints

    Returns
    -------
    list of n RawPoints sharing one contiguous allocation.
    """
    n = len(scalars)
    if n == 0:
        raise ValueError("empty input")
    if n != len(points):
        raise ValueError("scalars and points must have the same length")

    packed_s    = b"".join(scalars)
    PtrArrayIn  = ctypes.c_void_p * n
    PtrArrayOut = ctypes.c_void_p * n
    in_ptrs     = PtrArrayIn(*(p._ptr for p in points))
    out_ptrs    = PtrArrayOut()

    ret = _lib.c_batch_scalarmult_pairs_raw(
        out_ptrs, packed_s, in_ptrs, ctypes.c_int(n),
    )
    if ret != 0:
        raise RuntimeError("c_batch_scalarmult_pairs_raw failed")

    block_ref = ctypes.c_void_p(out_ptrs[0])
    return [RawPoint(out_ptrs[i], batch_block=block_ref, lib=_lib)
            for i in range(n)]


def batch_nizk_hash_verify(a_hat_c: list, a_hat_r: list,
                            C_bytes: list, R_bytes: list,
                            G_bytes: bytes, H_bytes: bytes,
                            e_expected: bytes) -> bool:
    """
    Single-challenge NIZK verifier over the combined statement of n tuples.

    Encodes all points in parallel, then hashes the full combined statement
    once and checks against the single expected challenge.

    Parameters
    ----------
    a_hat_c    : list of n RawPoints — reconstructed Â_C_i
    a_hat_r    : list of n RawPoints — reconstructed Â_R_i
    C_bytes    : list of n bytes(32) — original commitment encodings
    R_bytes    : list of n bytes(32) — encoded r-commitment bytes
    G_bytes    : bytes(32) — generator G encoding
    H_bytes    : bytes(32) — generator H encoding
    e_expected : bytes(32) — single expected challenge scalar (little-endian)

    Returns
    -------
    True if the hash matches, False otherwise.
    """
    n = len(a_hat_c)
    if n == 0:
        return True

    PtrArray = ctypes.c_void_p * n
    ac_ptrs  = PtrArray(*(p._ptr for p in a_hat_c))
    ar_ptrs  = PtrArray(*(p._ptr for p in a_hat_r))

    ret = _lib.c_batch_nizk_hash_verify(
        ac_ptrs, ar_ptrs,
        b"".join(C_bytes), b"".join(R_bytes),
        G_bytes, H_bytes,
        e_expected,
        ctypes.c_int(n),
    )
    return ret == 1


def batch_nizk_hash_prove(a_c_pts: list, a_r_pts: list, r_pts: list,
                           C_bytes: list,
                           G_bytes: bytes, H_bytes: bytes,
                           kx_list: list, kr_list: list,
                           x_list:  list, r_list:  list) -> bytes:
    """
    Single-challenge NIZK prover over the combined statement of n tuples.

    Step 1 (parallel): encode all A_C[i], A_R[i], R[i].
    Step 2 (sequential): one SHA-512 over the full combined statement → single e.
    Step 3 (parallel): compute s_x_i = kx_i + e*x_i, s_r_i = kr_i + e*r_i.

    Parameters
    ----------
    a_c_pts : list of n RawPoints  — A_C_i = k_x*G + k_r*H
    a_r_pts : list of n RawPoints  — A_R_i = k_r*G
    r_pts   : list of n RawPoints  — R_i   = r*G
    C_bytes : list of n bytes(32)  — commitment encodings from bulletproofs
    G_bytes : bytes(32)
    H_bytes : bytes(32)
    kx_list : list of n bytes(32)  — nonce scalars k_x_i
    kr_list : list of n bytes(32)  — nonce scalars k_r_i
    x_list  : list of n bytes(32)  — message scalars x_i
    r_list  : list of n bytes(32)  — blinding scalars r_i

    Returns
    -------
    bytes(32 + n*64) — e (32) || s_x_0||s_r_0 (64) || ... || s_x_{n-1}||s_r_{n-1} (64)
    """
    n = len(a_c_pts)
    if n == 0:
        return b""

    PtrArray = ctypes.c_void_p * n
    ac_ptrs  = PtrArray(*(p._ptr for p in a_c_pts))
    ar_ptrs  = PtrArray(*(p._ptr for p in a_r_pts))
    r_ptrs   = PtrArray(*(p._ptr for p in r_pts))

    proof_buf = ctypes.create_string_buffer(32 + n * 64)

    ret = _lib.c_batch_nizk_hash_prove(
        ac_ptrs, ar_ptrs, r_ptrs,
        b"".join(C_bytes),
        G_bytes, H_bytes,
        b"".join(kx_list),
        b"".join(kr_list),
        b"".join(x_list),
        b"".join(r_list),
        proof_buf,
        ctypes.c_int(n),
    )
    if ret != 0:
        raise RuntimeError("c_batch_nizk_hash_prove failed")

    return bytes(proof_buf)


def batch_hash_enc(prf_bytes_list: list, payload: bytes):
    """
    For each PRF point encoding in prf_bytes_list (32 bytes each), computes in
    parallel via OpenMP:
        tag[i]    = SHA-256("TAG" || prf[i])
        key[i]    = SHA-256("KEY" || prf[i])
        cipher[i] = secretbox_easy(payload, zero_nonce, key[i])  # 48 bytes

    Returns (tags, ciphers) where:
        tags    — list of n 32-byte tag bytes
        ciphers — list of n 48-byte ciphertext bytes
    """
    n = len(prf_bytes_list)
    if n == 0:
        return [], []
    packed_prf  = b"".join(prf_bytes_list)
    tags_buf    = ctypes.create_string_buffer(n * 32)
    ciphers_buf = ctypes.create_string_buffer(n * 48)
    ret = _lib.c_batch_hash_enc(packed_prf, payload, tags_buf, ciphers_buf, ctypes.c_int(n))
    if ret != 0:
        raise RuntimeError("c_batch_hash_enc failed")
    tags    = [bytes(tags_buf[i*32:(i+1)*32])    for i in range(n)]
    ciphers = [bytes(ciphers_buf[i*48:(i+1)*48]) for i in range(n)]
    return tags, ciphers


def batch_sha256_tag_key(prf_bytes_list: list):
    """
    Computes SHA-256("TAG"||prf[i]) and SHA-256("KEY"||prf[i]) for all i in
    parallel. Returns (tags, keys), each a list of n 32-byte bytes objects.
    Used during audit before the Python DB lookup step.
    """
    n = len(prf_bytes_list)
    if n == 0:
        return [], []
    packed_prf = b"".join(prf_bytes_list)
    tags_buf   = ctypes.create_string_buffer(n * 32)
    keys_buf   = ctypes.create_string_buffer(n * 32)
    ret = _lib.c_batch_sha256_tag_key(packed_prf, tags_buf, keys_buf, ctypes.c_int(n))
    if ret != 0:
        raise RuntimeError("c_batch_sha256_tag_key failed")
    tags = [bytes(tags_buf[i*32:(i+1)*32]) for i in range(n)]
    keys = [bytes(keys_buf[i*32:(i+1)*32]) for i in range(n)]
    return tags, keys


def batch_secretbox_open_verify(keys_list: list, ciphers_list: list, expected: bytes) -> bool:
    """
    Decrypts and verifies n ciphertexts in parallel. Each cipher must be 48 bytes
    (as produced by batch_hash_enc). Returns True iff every decryption succeeds
    and the plaintext matches `expected` (32 bytes).
    """
    n = len(keys_list)
    if n == 0:
        return True
    packed_keys    = b"".join(keys_list)
    packed_ciphers = b"".join(ciphers_list)
    ret = _lib.c_batch_secretbox_open_verify(
        packed_keys, packed_ciphers, expected, ctypes.c_int(n))
    return ret == 1


def secretbox_open(key: bytes, cipher: bytes) -> bytes:
    """
    Decrypt a single 48-byte secretbox ciphertext (from batch_hash_enc) with
    the given 32-byte key. Returns the 32-byte plaintext, raises ValueError on
    authentication failure.
    """
    import ctypes as _ct
    import ctypes.util as _cu
    _sodium = _ct.CDLL(_cu.find_library("sodium"))
    _sodium.crypto_secretbox_open_easy.argtypes = [
        _ct.c_char_p, _ct.c_char_p, _ct.c_ulonglong, _ct.c_char_p, _ct.c_char_p]
    _sodium.crypto_secretbox_open_easy.restype = _ct.c_int
    ZERO_NONCE = b"\x00" * 24
    out = _ct.create_string_buffer(len(cipher) - 16)
    ret = _sodium.crypto_secretbox_open_easy(out, cipher, len(cipher), ZERO_NONCE, key)
    if ret != 0:
        raise ValueError("secretbox_open: authentication failed")
    return bytes(out)
