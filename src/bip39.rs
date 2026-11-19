//! Entropie, phrase mnémonique et seed.
use sha2::{Digest, Sha256};

/// Taille de l'entropie en octets : 128 bits pour une phrase de 12 mots.
pub const ENTROPY_BYTES: usize = 16;
/// Nombre de mots de la phrase : (128 bits + 4 bits de checksum) / 11.
pub const WORD_COUNT: usize = 12;
/// Chaque mot code 11 bits (2^11 = 2048 mots dans la liste).
const BITS_PER_WORD: usize = 11;

/// Tire 128 bits depuis l'aléa cryptographique du système d'exploitation.
pub fn generate_entropy() -> Result<[u8; ENTROPY_BYTES], getrandom::Error> {
    let mut entropy = [0u8; ENTROPY_BYTES];
    getrandom::fill(&mut entropy)?;
    Ok(entropy)
}

/// Checksum BIP39 : les 4 premiers bits du SHA-256 de l'entropie.
pub fn checksum(entropy: &[u8; ENTROPY_BYTES]) -> u8 {
    let hash = Sha256::digest(entropy);
    hash[0] >> 4
}

/// Entropie suivie du checksum, sous forme de chaîne de 132 caractères `0`/`1`.
pub fn bits_with_checksum(entropy: &[u8; ENTROPY_BYTES]) -> String {
    let mut bits = String::new();
    for octet in entropy {
        bits.push_str(&format!("{octet:08b}"));
    }
    bits.push_str(&format!("{:04b}", checksum(entropy)));
    bits
}

/// Découpe entropie + checksum en 12 groupes de 11 bits (un indice de mot par groupe).
pub fn word_indices(entropy: &[u8; ENTROPY_BYTES]) -> [usize; WORD_COUNT] {
    let bits = bits_with_checksum(entropy);
    std::array::from_fn(|i| {
        let group = &bits[i * BITS_PER_WORD..(i + 1) * BITS_PER_WORD];
        usize::from_str_radix(group, 2).expect("le groupe contient exactement 11 bits")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_et_indices_entropie_nulle() {
        assert_eq!(checksum(&[0; ENTROPY_BYTES]), 3);
        assert_eq!(word_indices(&[0; ENTROPY_BYTES]), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    }
}
