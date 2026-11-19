//! Clés maîtresses, chain code et dérivation des clés enfants (BIP32).
use hmac::{Hmac, KeyInit, Mac};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha512;

use crate::base58;

/// Taille d'une clé privée et d'un chain code (256 bits).
pub const KEY_BYTES: usize = 32;
/// Clé HMAC imposée par BIP32 pour la clé maîtresse.
const MASTER_HMAC_KEY: &[u8] = b"Bitcoin seed";
/// Préfixe de version d'une clé privée étendue sur le mainnet (« xprv »).
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Préfixe de version d'une clé publique étendue sur le mainnet (« xpub »).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Taille d'une clé publique compressée : préfixe 02/03 + abscisse sur 32 octets.
pub const PUBLIC_KEY_BYTES: usize = 33;

/// Clé privée étendue : clé privée + chain code + position dans l'arbre.
pub struct ExtendedKey {
    pub private_key: [u8; KEY_BYTES],
    pub chain_code: [u8; KEY_BYTES],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
}

/// HMAC-SHA512, coupé en deux moitiés de 32 octets (IL, IR).
fn hmac_sha512(key: &[u8], data: &[u8]) -> ([u8; KEY_BYTES], [u8; KEY_BYTES]) {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepte toute taille de clé");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let (left, right) = result.split_at(KEY_BYTES);
    (
        left.try_into().expect("32 octets"),
        right.try_into().expect("32 octets"),
    )
}

/// Clé maîtresse : IL = clé privée maîtresse, IR = chain code maître.
pub fn master_key(seed: &[u8]) -> Result<ExtendedKey, String> {
    let (private_key, chain_code) = hmac_sha512(MASTER_HMAC_KEY, seed);
    // BIP32 : la clé est invalide si IL vaut 0 ou dépasse l'ordre n de la courbe.
    SecretKey::from_slice(&private_key).map_err(|_| "clé maîtresse invalide pour cette seed")?;
    Ok(ExtendedKey {
        private_key,
        chain_code,
        depth: 0,
        parent_fingerprint: [0; 4],
        child_number: 0,
    })
}

impl ExtendedKey {
    /// Sérialisation BIP32 : version, profondeur, empreinte du parent, index, chain code, clé.
    fn serialize(&self, version: [u8; 4], key: &[u8]) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(&version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(key);
        base58::encode_check(&data)
    }

    /// Clé privée étendue (xprv), la clé privée est précédée d'un octet nul.
    pub fn xprv(&self) -> String {
        let mut key = vec![0];
        key.extend_from_slice(&self.private_key);
        self.serialize(XPRV_VERSION, &key)
    }

    /// Clé publique compressée (33 octets) : point K = k·G sur secp256k1.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let secret =
            SecretKey::from_slice(&self.private_key).expect("clé privée validée à la création");
        let point = secret.public_key().to_sec1_point(true);
        point
            .as_bytes()
            .try_into()
            .expect("clé compressée sur 33 octets")
    }

    /// Clé publique étendue (xpub) : même chain code, clé publique à la place de la privée.
    pub fn xpub(&self) -> String {
        self.serialize(XPUB_VERSION, &self.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// Vecteur de test 1 de BIP32.
    const SEED_VECTEUR_1: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn cle_maitresse_vecteur_1() {
        let master = master_key(&SEED_VECTEUR_1).unwrap();
        assert_eq!(
            hex::encode(&master.private_key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(&master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        assert_eq!(
            master.xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn cle_publique_maitresse_vecteur_1() {
        let master = master_key(&SEED_VECTEUR_1).unwrap();
        assert_eq!(
            hex::encode(&master.public_key()),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
        assert_eq!(
            master.xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }
}
