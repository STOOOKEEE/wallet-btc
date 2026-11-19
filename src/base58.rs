//! Encodage Base58Check, utilisé pour sérialiser les clés étendues (xprv / xpub).
use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE: u32 = 58;
/// Nombre d'octets du double SHA-256 ajoutés en fin de données.
const CHECKSUM_BYTES: usize = 4;

/// Ajoute 4 octets de checksum (double SHA-256) puis encode en Base58.
pub fn encode_check(data: &[u8]) -> String {
    let hash = Sha256::digest(Sha256::digest(data));
    let mut bytes = data.to_vec();
    bytes.extend_from_slice(&hash[..CHECKSUM_BYTES]);
    encode(&bytes)
}

/// Conversion base 256 → base 58 par divisions successives.
fn encode(bytes: &[u8]) -> String {
    // Chiffres en base 58, poids faible en premier.
    let mut digits: Vec<u32> = Vec::new();
    for &octet in bytes {
        let mut carry = u32::from(octet);
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % BASE;
            carry /= BASE;
        }
        while carry > 0 {
            digits.push(carry % BASE);
            carry /= BASE;
        }
    }

    // Chaque octet nul en tête est représenté par un « 1 ».
    let leading_zeros = bytes.iter().take_while(|&&octet| octet == 0).count();
    let mut text = "1".repeat(leading_zeros);
    for &digit in digits.iter().rev() {
        text.push(char::from(ALPHABET[digit as usize]));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodage_base58() {
        assert_eq!(encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(encode(&[0, 0, 1]), "112");
    }
}
