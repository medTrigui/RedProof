use redproof_artifact::{CommitmentAlgorithm, CommitmentSet, CommitmentWitness, EncodedBlob};
use sha2::{Digest, Sha256};

pub struct Transcript {
    pub handshake: Vec<u8>,
    pub app_data: Vec<u8>,
}

pub fn build_commitments(
    transcript: &Transcript,
    algorithm: CommitmentAlgorithm,
    include_witness: bool,
) -> CommitmentSet {
    let handshake = hash_bytes(&algorithm, &transcript.handshake);
    let app_data = hash_bytes(&algorithm, &transcript.app_data);
    let witness = if include_witness {
        Some(CommitmentWitness {
            handshake: EncodedBlob::from_bytes(&transcript.handshake),
            app_data: EncodedBlob::from_bytes(&transcript.app_data),
        })
    } else {
        None
    };

    CommitmentSet {
        algorithm,
        handshake,
        app_data,
        witness,
    }
}

fn hash_bytes(algo: &CommitmentAlgorithm, data: &[u8]) -> EncodedBlob {
    match algo {
        CommitmentAlgorithm::Blake3 => {
            let digest = blake3::hash(data);
            EncodedBlob::from_bytes(digest.as_bytes())
        }
        CommitmentAlgorithm::Sha256 => {
            let digest = Sha256::digest(data);
            EncodedBlob::from_bytes(&digest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_commitments_differ() {
        let transcript = Transcript {
            handshake: b"handshake".to_vec(),
            app_data: b"app".to_vec(),
        };
        let commitments = build_commitments(&transcript, CommitmentAlgorithm::Blake3, true);
        assert_ne!(commitments.handshake.0, commitments.app_data.0);
        assert!(commitments.witness.is_some());
    }
}
