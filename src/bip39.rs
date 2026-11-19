//! Entropie, phrase mnémonique et seed.
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

/// Taille de l'entropie en octets : 128 bits pour une phrase de 12 mots.
pub const ENTROPY_BYTES: usize = 16;
/// Nombre de mots de la phrase : (128 bits + 4 bits de checksum) / 11.
pub const WORD_COUNT: usize = 12;
/// Chaque mot code 11 bits (2^11 = 2048 mots dans la liste).
const BITS_PER_WORD: usize = 11;
/// Taille de la seed en octets (512 bits).
pub const SEED_BYTES: usize = 64;
/// Nombre d'itérations PBKDF2 imposé par BIP39.
const PBKDF2_ROUNDS: u32 = 2048;

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

/// Liste officielle anglaise BIP39 (2048 mots), embarquée à la compilation.
fn wordlist() -> Vec<&'static str> {
    include_str!("english.txt").lines().collect()
}

/// Phrase mnémonique : chaque indice de 11 bits est remplacé par le mot correspondant.
pub fn mnemonic(entropy: &[u8; ENTROPY_BYTES]) -> String {
    let words = wordlist();
    word_indices(entropy).map(|index| words[index]).join(" ")
}

/// Import d'une phrase : vérifie le nombre de mots, chaque mot et le checksum,
/// puis renvoie l'entropie d'origine.
pub fn entropy_from_mnemonic(phrase: &str) -> Result<[u8; ENTROPY_BYTES], String> {
    let words = wordlist();
    let saisis: Vec<&str> = phrase.split_whitespace().collect();
    if saisis.len() != WORD_COUNT {
        return Err(format!(
            "la phrase doit contenir {WORD_COUNT} mots ({} reçus)",
            saisis.len()
        ));
    }

    let mut bits = String::new();
    for mot in saisis {
        let index = words
            .binary_search(&mot)
            .map_err(|_| format!("mot absent de la liste BIP39 : « {mot} »"))?;
        bits.push_str(&format!("{index:011b}"));
    }

    let mut entropy = [0u8; ENTROPY_BYTES];
    for (i, octet) in entropy.iter_mut().enumerate() {
        *octet = u8::from_str_radix(&bits[i * 8..(i + 1) * 8], 2).expect("8 bits binaires");
    }
    if bits_with_checksum(&entropy) != bits {
        return Err("checksum invalide : un mot est faux ou mal placé".to_string());
    }
    Ok(entropy)
}

/// Seed BIP39 : PBKDF2-HMAC-SHA512 de la phrase, avec le sel « mnemonic » + passphrase.
/// Les deux chaînes sont normalisées en NFKD comme l'exige BIP39.
pub fn seed(mnemonic: &str, passphrase: &str) -> [u8; SEED_BYTES] {
    let password: String = mnemonic.nfkd().collect();
    let salt: String = format!("mnemonic{passphrase}").nfkd().collect();
    pbkdf2_hmac_array::<Sha512, SEED_BYTES>(password.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_et_indices_entropie_nulle() {
        assert_eq!(checksum(&[0; ENTROPY_BYTES]), 3);
        assert_eq!(word_indices(&[0; ENTROPY_BYTES]), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    }

    #[test]
    fn liste_officielle_complete_et_triee() {
        let words = wordlist();
        assert_eq!(words.len(), 2048);
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn vecteurs_de_reference_bip39() {
        // Source : trezor/python-mnemonic, vectors.json (anglais).
        for (entropy, expected) in [
            (
                [0; 16],
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ),
            (
                [0x7f; 16],
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            ),
            (
                [0x80; 16],
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            ),
            ([0xff; 16], "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
            (
                [
                    0x9e, 0x88, 0x5d, 0x95, 0x2a, 0xd3, 0x62, 0xca, 0xeb, 0x4e, 0xfe, 0x34, 0xa8,
                    0xe9, 0x1b, 0xd2,
                ],
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            ),
        ] {
            assert_eq!(mnemonic(&entropy), expected);
            assert_eq!(entropy_from_mnemonic(expected), Ok(entropy));
        }
    }

    #[test]
    fn import_refuse_les_phrases_invalides() {
        let mauvais_checksum = "abandon ".repeat(12);
        assert!(entropy_from_mnemonic(&mauvais_checksum).is_err());
        assert!(entropy_from_mnemonic("abandon abandon about").is_err());
        let mot_inconnu = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bitcoin";
        assert!(entropy_from_mnemonic(mot_inconnu).is_err());
    }

    #[test]
    fn seed_vecteur_de_reference() {
        // Vecteur trezor : entropie nulle, passphrase « TREZOR ».
        let phrase = mnemonic(&[0; ENTROPY_BYTES]);
        assert_eq!(
            crate::hex::encode(&seed(&phrase, "TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }
}
