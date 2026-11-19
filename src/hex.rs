//! Affichage hexadécimal des octets.

/// Représentation hexadécimale (minuscules) d'une suite d'octets.
pub fn encode(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}
