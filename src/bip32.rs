//! Clés maîtresses, chain code et dérivation des clés enfants (BIP32).
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{Scalar, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

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
/// Les index à partir de 2^31 désignent des enfants renforcés (notés `i'`).
pub const HARDENED_OFFSET: u32 = 1 << 31;

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

/// Dérive la clé d'un chemin complet, par ex. `m/44'/0'/0'/0/5` :
/// le niveau M est le nombre d'index, le dernier index est N.
pub fn derive_path(master: ExtendedKey, path: &str) -> Result<ExtendedKey, String> {
    let mut parts = path.split('/');
    if parts.next() != Some("m") {
        return Err("le chemin doit commencer par « m », par ex. m/44'/0'/0'/0/5".to_string());
    }
    let mut key = master;
    for part in parts {
        key = key.derive_child(parse_index(part)?)?;
    }
    Ok(key)
}

/// Lit un index : `5` (normal) ou `5'` / `5h` (renforcé, soit 5 + 2^31).
pub fn parse_index(text: &str) -> Result<u32, String> {
    let (number, hardened) = match text.strip_suffix(['\'', 'h']) {
        Some(number) => (number, true),
        None => (text, false),
    };
    let index: u32 = number
        .parse()
        .map_err(|_| format!("index invalide : « {text} »"))?;
    if index >= HARDENED_OFFSET {
        return Err(format!(
            "index trop grand : « {text} » (maximum 2147483647)"
        ));
    }
    Ok(if hardened {
        index + HARDENED_OFFSET
    } else {
        index
    })
}

/// Écriture d'un index dans un chemin : `5` ou `5'` pour un index renforcé.
pub fn format_index(index: u32) -> String {
    if index >= HARDENED_OFFSET {
        format!("{}'", index - HARDENED_OFFSET)
    } else {
        index.to_string()
    }
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

    /// Empreinte de la clé : 4 premiers octets de RIPEMD160(SHA256(clé publique)).
    fn fingerprint(&self) -> [u8; 4] {
        let hash = Ripemd160::digest(Sha256::digest(self.public_key()));
        hash[..4].try_into().expect("4 octets")
    }

    /// CKDpriv : dérive la clé enfant d'index `index` (renforcée si index ≥ 2^31).
    pub fn derive_child(&self, index: u32) -> Result<ExtendedKey, String> {
        // Enfant renforcé : 0x00 || clé privée ; enfant normal : clé publique.
        let mut data = Vec::new();
        if index >= HARDENED_OFFSET {
            data.push(0);
            data.extend_from_slice(&self.private_key);
        } else {
            data.extend_from_slice(&self.public_key());
        }
        data.extend_from_slice(&index.to_be_bytes());
        let (il, chain_code) = hmac_sha512(&self.chain_code, &data);

        // Clé enfant = (IL + clé parent) mod n. Invalide si IL ≥ n ou si le résultat est nul.
        let il: Option<Scalar> = Scalar::from_repr(il.into()).into();
        let il = il.ok_or("index invalide (IL ≥ n), essayer l'index suivant")?;
        let parent =
            SecretKey::from_slice(&self.private_key).expect("clé privée validée à la création");
        let child = il + *parent.to_nonzero_scalar();
        SecretKey::from_bytes(&child.to_bytes())
            .map_err(|_| "index invalide (clé nulle), essayer l'index suivant")?;

        Ok(ExtendedKey {
            private_key: child.to_bytes().into(),
            chain_code,
            depth: self
                .depth
                .checked_add(1)
                .ok_or("profondeur maximale (255) atteinte")?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
        })
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

    #[test]
    fn cles_enfants_vecteur_1() {
        // m/0' (renforcé) puis m/0'/1 (normal).
        let enfant = master_key(&SEED_VECTEUR_1)
            .unwrap()
            .derive_child(HARDENED_OFFSET)
            .unwrap();
        assert_eq!(
            enfant.xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
        let petit_enfant = enfant.derive_child(1).unwrap();
        assert_eq!(
            petit_enfant.xpub(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );
    }

    #[test]
    fn lecture_des_index() {
        assert_eq!(parse_index("5"), Ok(5));
        assert_eq!(parse_index("5'"), Ok(5 + HARDENED_OFFSET));
        assert_eq!(parse_index("5h"), Ok(5 + HARDENED_OFFSET));
        assert!(parse_index("-1").is_err());
        assert!(parse_index("abc").is_err());
        assert!(parse_index("2147483648").is_err());
        assert_eq!(format_index(5 + HARDENED_OFFSET), "5'");
    }

    #[test]
    fn chemin_complet_vecteur_1() {
        let master = master_key(&SEED_VECTEUR_1).unwrap();
        let cle = derive_path(master, "m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(cle.depth, 5);
        assert_eq!(
            cle.xprv(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
        assert_eq!(
            cle.xpub(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        );
    }

    #[test]
    fn chemins_invalides() {
        for chemin in ["0/1", "m/", "m/1/x", "m//1"] {
            let master = master_key(&SEED_VECTEUR_1).unwrap();
            assert!(derive_path(master, chemin).is_err(), "{chemin}");
        }
    }
}
