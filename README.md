# BioPAKE: Asymmetric Fuzzy PAKE for Remote Biometric Authentication

This repository accompanies **BioPAKE**, a practical asymmetric fuzzy password-authenticated key exchange (afPAKE) construction for privacy-preserving remote biometric authentication.

BioPAKE enables a client to authenticate with a fresh biometric reading that is close to its enrolled template, while the server retains only a one-way protected representation of that template. Consequently, a compromise of server-held biometric data permits no more than an exhaustive brute-force search for the underlying biometric.

The construction combines cosine locality-sensitive hashing with a small-error-set afPAKE technique to support proximity-based authentication over real-valued biometric embeddings under angular (cosine) distance. The included notebooks implement the protocol and evaluate false-positive/false-negative behavior on facial embeddings.

## Repository contents

- `Implementation.ipynb` - BioPAKE implementation and protocol experiments.
- `FP_FN-Experiment.ipynb` - false-positive and false-negative evaluation.
- `jiayu_safPAKE.ipynb` - supporting safe-PAKE experiments.
- `results/` - generated experimental results.

## Paper

**Asymmetric Fuzzy PAKE for Remote Biometric Authentication with Protection of Server-held Biometric Data** (NDSS Symposium 2026).

The prototype evaluation reports facial-biometric configurations achieving over 90% true acceptance at false-acceptance rates of 2^-30, 2^-40, and 2^-50, with combined authentication times of 0.64 s, 2.34 s, and 9.16 s, respectively.

## Main contributors

This work was principally developed by:

- **Jinyao Xu**
- **Apurva Rai**

## Note

This repository is research code intended to accompany the paper. It has not been packaged or audited as production authentication software.
