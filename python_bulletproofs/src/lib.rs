use pyo3::prelude::*;
use pyo3::types::PyBytes;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::rngs::OsRng;

/// Creates a standard Bulletproof range proof with a random blinder
#[pyfunction]
fn prove_range<'a>(
    py: Python<'a>, 
    secret_value: u64, 
    bit_length: usize
) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
    
    // DEFAULT: Uses standard G for value, and an orthogonal H for blinder
    let pc_gens = PedersenGens::default(); 
    let bp_gens = BulletproofGens::new(64, 1);
    
    let blinding_factor = Scalar::random(&mut OsRng);
    let mut prover_transcript = Transcript::new(b"FaceZKRangeProof");
    
    let (proof, commitment) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding_factor,
        bit_length,
    ).expect("Failed to generate range proof");

    Ok((
        PyBytes::new(py, &commitment.to_bytes()),
        PyBytes::new(py, &proof.to_bytes())
    ))
}

/// Verifies a standard Bulletproof range proof
#[pyfunction]
fn verify_range(commitment_bytes: &[u8], proof_bytes: &[u8], bit_length: usize) -> PyResult<bool> {
    
    // DEFAULT: Uses standard G for value, and an orthogonal H for blinder
    let pc_gens = PedersenGens::default(); 
    let bp_gens = BulletproofGens::new(64, 1);
    
    if commitment_bytes.len() != 32 { return Ok(false); }
    let mut comm_arr = [0u8; 32];
    comm_arr.copy_from_slice(commitment_bytes);
    let commitment = CompressedRistretto(comm_arr);

    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(p) => p, Err(_) => return Ok(false),
    };
    
    let mut verifier_transcript = Transcript::new(b"FaceZKRangeProof");
    let is_valid = proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &commitment, bit_length).is_ok();

    Ok(is_valid)
}

/// Creates a Bulletproof range proof using a *specific* blinder (standard generators)
#[pyfunction]
fn prove_range_with_blinder<'a>(
    py: Python<'a>, 
    secret_value: u64, 
    bit_length: usize,
    blinder_bytes: &[u8]
) -> PyResult<(&'a PyBytes, &'a PyBytes)> {
    
    // DEFAULT: Uses standard G for value, and an orthogonal H for blinder
    let pc_gens = PedersenGens::default(); 
    let bp_gens = BulletproofGens::new(64, 1);
    
    // Deserialize your custom Blinder
    let mut blinder_arr = [0u8; 32];
    blinder_arr.copy_from_slice(blinder_bytes);
    let blinding_factor = Scalar::from_bytes_mod_order(blinder_arr);
    
    let mut prover_transcript = Transcript::new(b"FaceZKRangeProof");
    
    let (proof, commitment) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding_factor,
        bit_length,
    ).expect("Failed to generate range proof");

    Ok((
        PyBytes::new(py, &commitment.to_bytes()),
        PyBytes::new(py, &proof.to_bytes())
    ))
}

/// Returns Dalek's default H (blinding generator) as 32 bytes
#[pyfunction]
fn get_dalek_default_h<'a>(py: Python<'a>) -> PyResult<&'a PyBytes> {
    let pc_gens = PedersenGens::default();
    // B_blinding is Dalek's default H
    let h_bytes = pc_gens.B_blinding.compress().to_bytes(); 
    Ok(PyBytes::new(py, &h_bytes))
}

#[pymodule]
fn python_bulletproofs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_with_blinder, m)?)?;
    m.add_function(wrap_pyfunction!(get_dalek_default_h, m)?)?; // NEW
    Ok(())
}