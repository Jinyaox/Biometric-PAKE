use pyo3::prelude::*;
use pyo3::types::PyBytes;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::rngs::OsRng;
use std::sync::OnceLock;
use curve25519_dalek_ng::ristretto::RistrettoBasepointTable;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ── Generator caches ───────────────────────────────────────────────────────

static PC_GENS: OnceLock<PedersenGens>            = OnceLock::new();
static G_TABLE: OnceLock<RistrettoBasepointTable> = OnceLock::new();
static H_TABLE: OnceLock<RistrettoBasepointTable> = OnceLock::new();

// Keyed by bit_length — for single-proof and batch-single functions.
static BP_CACHE: OnceLock<Mutex<HashMap<usize, Arc<BulletproofGens>>>> = OnceLock::new();

// Keyed by (bit_length, n) — for aggregated prove/verify.
static AGG_BP_CACHE: OnceLock<Mutex<HashMap<(usize, usize), Arc<BulletproofGens>>>> =
    OnceLock::new();

fn pc_gens() -> &'static PedersenGens {
    PC_GENS.get_or_init(PedersenGens::default)
}

fn g_table() -> &'static RistrettoBasepointTable {
    G_TABLE.get_or_init(|| RistrettoBasepointTable::create(&pc_gens().B))
}

fn h_table() -> &'static RistrettoBasepointTable {
    H_TABLE.get_or_init(|| RistrettoBasepointTable::create(&pc_gens().B_blinding))
}

/// BulletproofGens for n=1 at the given bit length.
fn bp_gens_for(bit_length: usize) -> Arc<BulletproofGens> {
    let cache = BP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    map.entry(bit_length)
        .or_insert_with(|| Arc::new(BulletproofGens::new(bit_length, 1)))
        .clone()
}

/// BulletproofGens for n values at the given bit length (aggregated proofs).
fn agg_bp_gens_for(bit_length: usize, n: usize) -> Arc<BulletproofGens> {
    let cache = AGG_BP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    map.entry((bit_length, n))
        .or_insert_with(|| Arc::new(BulletproofGens::new(bit_length, n)))
        .clone()
}

// ── Single prove/verify ────────────────────────────────────────────────────

/// Creates a standard Bulletproof range proof with a random blinder.
#[pyfunction]
fn prove_range<'a>(
    py: Python<'a>,
    secret_value: u64,
    bit_length: usize,
) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
    let bp_gens = bp_gens_for(bit_length);
    let pc_gens = pc_gens();

    let blinding_factor = Scalar::random(&mut OsRng);
    let mut transcript  = Transcript::new(b"FaceZKRangeProof");

    let (proof, commitment) = RangeProof::prove_single(
        &*bp_gens,
        pc_gens,
        &mut transcript,
        secret_value,
        &blinding_factor,
        bit_length,
    )
    .expect("Failed to generate range proof");

    Ok((
        PyBytes::new(py, &commitment.to_bytes()),
        PyBytes::new(py, &proof.to_bytes()),
    ))
}

/// Verifies a standard Bulletproof range proof.
#[pyfunction]
fn verify_range(
    commitment_bytes: &[u8],
    proof_bytes: &[u8],
    bit_length: usize,
) -> PyResult<bool> {
    if commitment_bytes.len() != 32 {
        return Ok(false);
    }

    let bp_gens = bp_gens_for(bit_length);
    let pc_gens = pc_gens();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(commitment_bytes);
    let commitment = CompressedRistretto(arr);

    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(p)  => p,
        Err(_) => return Ok(false),
    };

    let mut transcript = Transcript::new(b"FaceZKRangeProof");
    Ok(proof
        .verify_single(&*bp_gens, pc_gens, &mut transcript, &commitment, bit_length)
        .is_ok())
}

/// Creates a Bulletproof range proof using a specific blinder.
#[pyfunction]
fn prove_range_with_blinder<'a>(
    py: Python<'a>,
    secret_value: u64,
    bit_length: usize,
    blinder_bytes: &[u8],
) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
    if blinder_bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "blinder_bytes must be exactly 32 bytes",
        ));
    }

    let bp_gens = bp_gens_for(bit_length);
    let pc_gens = pc_gens();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(blinder_bytes);
    let blinding_factor = Scalar::from_bytes_mod_order(arr);

    let mut transcript = Transcript::new(b"FaceZKRangeProof");
    let (proof, commitment) = RangeProof::prove_single(
        &*bp_gens,
        pc_gens,
        &mut transcript,
        secret_value,
        &blinding_factor,
        bit_length,
    )
    .expect("Failed to generate range proof");

    Ok((
        PyBytes::new(py, &commitment.to_bytes()),
        PyBytes::new(py, &proof.to_bytes()),
    ))
}

// ── Batch prove/verify (parallel independent proofs) ──────────────────────

/// Proves each (secret_value, blinder) pair independently, in parallel via Rayon.
/// Returns (commitments, proofs) in the same order as input.
#[pyfunction]
fn prove_range_batch<'a>(
    py: Python<'a>,
    secret_values: Vec<u64>,
    blinder_bytes_list: Vec<Vec<u8>>,
    bit_length: usize,
) -> PyResult<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    if secret_values.len() != blinder_bytes_list.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "secret_values and blinder_bytes_list must have the same length",
        ));
    }
    if secret_values.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }

    let bp_gens = bp_gens_for(bit_length);
    let pc_gens = pc_gens();

    let results: PyResult<Vec<(Vec<u8>, Vec<u8>)>> = py.allow_threads(|| {
        secret_values
            .par_iter()
            .zip(blinder_bytes_list.par_iter())
            .map(|(secret_value, blinder_bytes)| {
                if blinder_bytes.len() != 32 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Each blinder must be exactly 32 bytes",
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(blinder_bytes);
                let blinding_factor = Scalar::from_bytes_mod_order(arr);

                let mut transcript = Transcript::new(b"FaceZKRangeProof");
                let (proof, commitment) = RangeProof::prove_single(
                    &*bp_gens,
                    pc_gens,
                    &mut transcript,
                    *secret_value,
                    &blinding_factor,
                    bit_length,
                )
                .map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("{e:?}"))
                })?;

                Ok((commitment.to_bytes().to_vec(), proof.to_bytes()))
            })
            .collect()
    });

    let (commitments, proofs) = results?.into_iter().unzip();
    Ok((commitments, proofs))
}

/// Verifies each (commitment, proof) pair independently, in parallel via Rayon.
/// Returns a list of bools in the same order as input.
#[pyfunction]
fn verify_range_batch(
    py: Python<'_>,
    commitment_bytes_list: Vec<Vec<u8>>,
    proof_bytes_list: Vec<Vec<u8>>,
    bit_length: usize,
) -> PyResult<Vec<bool>> {
    if commitment_bytes_list.len() != proof_bytes_list.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "commitment_bytes_list and proof_bytes_list must have the same length",
        ));
    }
    if commitment_bytes_list.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }

    let bp_gens = bp_gens_for(bit_length);
    let pc_gens = pc_gens();

    py.allow_threads(|| {
        commitment_bytes_list
            .par_iter()
            .zip(proof_bytes_list.par_iter())
            .map(|(commitment_bytes, proof_bytes)| {
                if commitment_bytes.len() != 32 {
                    return Ok(false);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(commitment_bytes);
                let commitment = CompressedRistretto(arr);

                let proof = match RangeProof::from_bytes(proof_bytes) {
                    Ok(p)  => p,
                    Err(_) => return Ok(false),
                };

                let mut transcript = Transcript::new(b"FaceZKRangeProof");
                Ok(proof
                    .verify_single(&*bp_gens, pc_gens, &mut transcript, &commitment, bit_length)
                    .is_ok())
            })
            .collect()
    })
}

// ── Aggregated prove/verify (single proof for n values) ───────────────────

/// Proves all n (secret_value, blinder) pairs in one aggregated proof.
/// n must be a power of two. Returns (commitments: Vec<bytes>, proof: bytes).
/// Proof size is O(log(n * bit_length)) vs O(n * log(bit_length)) for batch.
#[pyfunction]
fn prove_range_aggregate<'a>(
    py: Python<'a>,
    secret_values: Vec<u64>,
    blinder_bytes_list: Vec<Vec<u8>>,
    bit_length: usize,
) -> PyResult<(Vec<Vec<u8>>, Vec<u8>)> {
    let n = secret_values.len();
    if n == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }
    if n != blinder_bytes_list.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "secret_values and blinder_bytes_list must have the same length",
        ));
    }
    if !n.is_power_of_two() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "n must be a power of two for aggregated proving (pad with dummy values if needed)",
        ));
    }

    let bp_gens = agg_bp_gens_for(bit_length, n);
    let pc_gens = pc_gens();

    py.allow_threads(|| {
        let blindings: PyResult<Vec<Scalar>> = blinder_bytes_list
            .iter()
            .map(|b| {
                if b.len() != 32 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Each blinder must be exactly 32 bytes",
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(Scalar::from_bytes_mod_order(arr))
            })
            .collect();
        let blindings = blindings?;

        let mut transcript = Transcript::new(b"FaceZKRangeProof");
        let (proof, commitments) = RangeProof::prove_multiple(
            &*bp_gens,
            pc_gens,
            &mut transcript,
            &secret_values,
            &blindings,
            bit_length,
        )
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e:?}")))?;

        let comm_bytes: Vec<Vec<u8>> = commitments
            .iter()
            .map(|c| c.to_bytes().to_vec())
            .collect();

        Ok((comm_bytes, proof.to_bytes()))
    })
}

/// Verifies one aggregated proof against n commitments in a single batch MSM.
#[pyfunction]
fn verify_range_aggregate(
    py: Python<'_>,
    commitment_bytes_list: Vec<Vec<u8>>,
    proof_bytes: Vec<u8>,
    bit_length: usize,
) -> PyResult<bool> {
    let n = commitment_bytes_list.len();
    if n == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }

    let bp_gens = agg_bp_gens_for(bit_length, n);
    let pc_gens = pc_gens();

    py.allow_threads(|| {
        let commitments: PyResult<Vec<CompressedRistretto>> = commitment_bytes_list
            .iter()
            .map(|b| {
                if b.len() != 32 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Each commitment must be exactly 32 bytes",
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(CompressedRistretto(arr))
            })
            .collect();

        let commitments = match commitments {
            Ok(c)  => c,
            Err(_) => return Ok(false),
        };

        let proof = match RangeProof::from_bytes(&proof_bytes) {
            Ok(p)  => p,
            Err(_) => return Ok(false),
        };

        let mut transcript = Transcript::new(b"FaceZKRangeProof");
        Ok(proof
            .verify_multiple(&*bp_gens, pc_gens, &mut transcript, &commitments, bit_length)
            .is_ok())
    })
}

// ── Parallel aggregated prove/verify (K chunks × chunk_size values) ──────

/// Proves N values as K parallel aggregated proofs, each covering `chunk_size` values.
///
/// This combines the parallelism of `prove_range_batch` with the compact proof size
/// of `prove_range_aggregate`:
///   - Proving:      K independent `prove_multiple` calls run in parallel via Rayon.
///   - Verification: K small aggregated MSMs run in parallel — much faster than
///                   N individual `verify_single` calls.
///
/// `chunk_size` must be a power of two.
/// If `len(secret_values)` is not divisible by `chunk_size`, the last chunk is
/// padded with zeros and zero blinders (dummy in-range values).
///
/// Returns `(commitments_per_chunk, proofs)`:
///   - `commitments_per_chunk[k]` is the list of 32-byte commitments for chunk k
///     (includes padding commitments if the last chunk was padded).
///   - `proofs[k]` is the serialised aggregated proof for chunk k.
#[pyfunction]
fn prove_range_aggregate_parallel<'a>(
    py: Python<'a>,
    secret_values: Vec<u64>,
    blinder_bytes_list: Vec<Vec<u8>>,
    bit_length: usize,
    chunk_size: usize,
) -> PyResult<(Vec<Vec<Vec<u8>>>, Vec<Vec<u8>>)> {
    let n = secret_values.len();
    if n == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }
    if n != blinder_bytes_list.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "secret_values and blinder_bytes_list must have the same length",
        ));
    }
    if !chunk_size.is_power_of_two() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "chunk_size must be a power of two",
        ));
    }

    // Build padded chunks (last chunk may be padded with zeros).
    let num_chunks = (n + chunk_size - 1) / chunk_size;
    let mut chunks: Vec<(Vec<u64>, Vec<Vec<u8>>)> = Vec::with_capacity(num_chunks);
    for c in 0..num_chunks {
        let start = c * chunk_size;
        let end   = (start + chunk_size).min(n);
        let mut sv = secret_values[start..end].to_vec();
        let mut bl = blinder_bytes_list[start..end].to_vec();
        // Pad to chunk_size
        while sv.len() < chunk_size {
            sv.push(0u64);
            bl.push(vec![0u8; 32]);
        }
        chunks.push((sv, bl));
    }

    let bp_gens = agg_bp_gens_for(bit_length, chunk_size);
    let pc_gens = pc_gens();

    let results: PyResult<Vec<(Vec<Vec<u8>>, Vec<u8>)>> = py.allow_threads(|| {
        chunks
            .par_iter()
            .map(|(sv_chunk, bl_chunk)| {
                let blindings: PyResult<Vec<Scalar>> = bl_chunk
                    .iter()
                    .map(|b| {
                        if b.len() != 32 {
                            return Err(pyo3::exceptions::PyValueError::new_err(
                                "Each blinder must be exactly 32 bytes",
                            ));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(b);
                        Ok(Scalar::from_bytes_mod_order(arr))
                    })
                    .collect();
                let blindings = blindings?;

                let mut transcript = Transcript::new(b"FaceZKRangeProof");
                let (proof, commitments) = RangeProof::prove_multiple(
                    &*bp_gens,
                    pc_gens,
                    &mut transcript,
                    sv_chunk,
                    &blindings,
                    bit_length,
                )
                .map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("{e:?}"))
                })?;

                let comm_bytes: Vec<Vec<u8>> =
                    commitments.iter().map(|c| c.to_bytes().to_vec()).collect();
                Ok((comm_bytes, proof.to_bytes()))
            })
            .collect()
    });

    let (all_commitments, all_proofs) = results?.into_iter().unzip();
    Ok((all_commitments, all_proofs))
}

/// Verifies K parallel aggregated proofs produced by `prove_range_aggregate_parallel`.
///
/// `commitments_per_chunk[k]` is the list of commitments for chunk k.
/// `proofs[k]` is the serialised proof for chunk k.
/// All chunks are verified in parallel via Rayon.
/// Returns `True` iff every chunk verifies successfully.
#[pyfunction]
fn verify_range_aggregate_parallel(
    py: Python<'_>,
    commitments_per_chunk: Vec<Vec<Vec<u8>>>,
    proofs: Vec<Vec<u8>>,
    bit_length: usize,
) -> PyResult<bool> {
    if commitments_per_chunk.len() != proofs.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "commitments_per_chunk and proofs must have the same length",
        ));
    }
    if commitments_per_chunk.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty input"));
    }

    // All chunks must have the same size (chunk_size), which must be a power of two.
    let chunk_size = commitments_per_chunk[0].len();
    if !chunk_size.is_power_of_two() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "chunk_size (commitments_per_chunk[0].len()) must be a power of two",
        ));
    }

    let bp_gens = agg_bp_gens_for(bit_length, chunk_size);
    let pc_gens = pc_gens();

    py.allow_threads(|| {
        let all_ok: bool = commitments_per_chunk
            .par_iter()
            .zip(proofs.par_iter())
            .map(|(comm_list, proof_bytes)| {
                let commitments: Vec<CompressedRistretto> = comm_list
                    .iter()
                    .filter_map(|b| {
                        if b.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(b);
                        Some(CompressedRistretto(arr))
                    })
                    .collect();

                if commitments.len() != comm_list.len() {
                    return false; // malformed commitment
                }

                let proof = match RangeProof::from_bytes(proof_bytes) {
                    Ok(p)  => p,
                    Err(_) => return false,
                };

                let mut transcript = Transcript::new(b"FaceZKRangeProof");
                proof
                    .verify_multiple(
                        &*bp_gens,
                        pc_gens,
                        &mut transcript,
                        &commitments,
                        bit_length,
                    )
                    .is_ok()
            })
            .all(|ok| ok);

        Ok(all_ok)
    })
}

// ── Generator export / Pedersen commit ────────────────────────────────────

static G_BYTES: OnceLock<[u8; 32]> = OnceLock::new();
static H_BYTES: OnceLock<[u8; 32]> = OnceLock::new();

#[pyfunction]
fn get_dalek_default_g<'a>(py: Python<'a>) -> PyResult<&'a PyBytes> {
    let bytes = G_BYTES.get_or_init(|| pc_gens().B.compress().to_bytes());
    Ok(PyBytes::new(py, bytes))
}

#[pyfunction]
fn get_dalek_default_h<'a>(py: Python<'a>) -> PyResult<&'a PyBytes> {
    let bytes = H_BYTES.get_or_init(|| pc_gens().B_blinding.compress().to_bytes());
    Ok(PyBytes::new(py, bytes))
}

/// Compute a Pedersen commitment C = value*B + blinding*B_blinding via table lookup.
#[pyfunction]
fn pedersen_commit<'a>(
    py: Python<'a>,
    value_bytes: &[u8],
    blinder_bytes: &[u8],
) -> PyResult<&'a PyBytes> {
    let mut value_arr   = [0u8; 32];
    let mut blinder_arr = [0u8; 32];
    value_arr.copy_from_slice(value_bytes);
    blinder_arr.copy_from_slice(blinder_bytes);

    let value_scalar    = Scalar::from_bytes_mod_order(value_arr);
    let blinding_factor = Scalar::from_bytes_mod_order(blinder_arr);

    let commitment = &value_scalar * g_table() + &blinding_factor * h_table();

    Ok(PyBytes::new(py, &commitment.compress().to_bytes()))
}

// ── Module ─────────────────────────────────────────────────────────────────

#[pymodule]
fn python_bulletproofs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_with_blinder, m)?)?;
    m.add_function(wrap_pyfunction!(get_dalek_default_g, m)?)?;
    m.add_function(wrap_pyfunction!(get_dalek_default_h, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_commit, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_batch, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_batch, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_aggregate_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_aggregate_parallel, m)?)?;
    Ok(())
}