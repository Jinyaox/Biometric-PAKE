# BioPAKE: Asymmetric Fuzzy PAKE for Remote Biometric Authentication

This repository accompanies **BioPAKE**, a practical asymmetric fuzzy password-authenticated key exchange (afPAKE) construction for privacy-preserving remote biometric authentication.

BioPAKE enables a client to authenticate with a fresh biometric reading that is close to its enrolled template, while the server retains only a one-way protected representation of that template. Consequently, a compromise of server-held biometric data permits no more than an exhaustive brute-force search for the underlying biometric.

The construction combines cosine locality-sensitive hashing with a small-error-set afPAKE technique to support proximity-based authentication over real-valued biometric embeddings under angular (cosine) distance. The included notebooks implement the protocol and evaluate false-positive/false-negative behavior on facial embeddings.

## Repository contents

Please use the Apurva-Working-Branch for the most up-to-date implementation

## Paper

**Asymmetric Fuzzy PAKE for Remote Biometric Authentication with Protection of Server-held Biometric Data** (Under Review).

## Main contributors

This github Repository is Developed and Maintained by:

- **Jinyao Xu**
- **Apurva Rai**

With EQUAL CONTRIBUTION

The Actual Paper is Developed By:

- **Jinyao Xu**
- **Apurva Rai**
- **Phillip Nazarian**
- **Ian G Harris**
- **Stanislaw Jarecki**

ALL With EQUAL CONTRIBUTION

## Note

This repository is research code intended to accompany the paper. It has not been packaged or audited as production authentication software.
