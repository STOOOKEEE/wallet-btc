//! Entropie, phrase mnémonique et seed.

/// Taille de l'entropie en octets : 128 bits pour une phrase de 12 mots.
pub const ENTROPY_BYTES: usize = 16;

/// Tire 128 bits depuis l'aléa cryptographique du système d'exploitation.
pub fn generate_entropy() -> Result<[u8; ENTROPY_BYTES], getrandom::Error> {
    let mut entropy = [0u8; ENTROPY_BYTES];
    getrandom::fill(&mut entropy)?;
    Ok(entropy)
}
