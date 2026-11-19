//! Menu interactif, saisies et affichage.
use std::io::{self, Write};

use crate::{bip32, bip39, hex};

/// Seed du wallet chargé pendant la session.
type Seed = [u8; bip39::SEED_BYTES];

/// Affiche une question et lit une ligne. Renvoie `None` en fin de saisie (Ctrl+D).
fn lire_ligne(question: &str) -> io::Result<Option<String>> {
    print!("{question}");
    io::stdout().flush()?;
    let mut ligne = String::new();
    if io::stdin().read_line(&mut ligne)? == 0 {
        return Ok(None);
    }
    Ok(Some(ligne.trim().to_string()))
}

fn generer() -> io::Result<Option<Seed>> {
    let entropy = match bip39::generate_entropy() {
        Ok(entropy) => entropy,
        Err(erreur) => {
            println!("Erreur de génération : {erreur}");
            return Ok(None);
        }
    };
    println!(
        "Entropie (entier 128 bits) : {}",
        u128::from_be_bytes(entropy)
    );
    afficher_representations(&entropy);
    let phrase = bip39::mnemonic(&entropy);
    println!("Phrase BIP39 : {phrase}");
    calculer_seed(&phrase)
}

fn importer() -> io::Result<Option<Seed>> {
    let Some(saisie) = lire_ligne("Phrase de 12 mots : ")? else {
        return Ok(None);
    };
    let entropy = match bip39::entropy_from_mnemonic(&saisie.to_lowercase()) {
        Ok(entropy) => entropy,
        Err(erreur) => {
            println!("Phrase refusée : {erreur}.");
            return Ok(None);
        }
    };
    println!("Phrase valide.");
    afficher_representations(&entropy);
    calculer_seed(&bip39::mnemonic(&entropy))
}

fn afficher_representations(entropy: &[u8; bip39::ENTROPY_BYTES]) {
    println!("Octets : {entropy:?}");
    println!("Hexadécimal : {}", hex::encode(entropy));
    println!("Checksum (4 bits) : {:04b}", bip39::checksum(entropy));
    println!(
        "Binaire + checksum : {}",
        bip39::bits_with_checksum(entropy)
    );
    println!("Groupes de 11 bits → indice :");
    for index in bip39::word_indices(entropy) {
        println!("  {index:011b} → {index}");
    }
}

/// Demande la passphrase facultative et calcule la seed de 512 bits.
fn calculer_seed(phrase: &str) -> io::Result<Option<Seed>> {
    let Some(passphrase) = lire_ligne("Passphrase (Entrée pour aucune) : ")? else {
        return Ok(None);
    };
    let seed = bip39::seed(phrase, &passphrase);
    println!("Seed BIP39 : {}", hex::encode(&seed));
    Ok(Some(seed))
}

fn afficher_cles_maitresses(seed: Option<&Seed>) {
    let Some(seed) = seed else {
        println!("Aucun wallet chargé : choisis d'abord 1 (générer) ou 2 (importer).");
        return;
    };
    match bip32::master_key(seed) {
        Ok(master) => afficher_cle(&master),
        Err(erreur) => println!("Erreur : {erreur}."),
    }
}

fn afficher_cle(cle: &bip32::ExtendedKey) {
    println!("Clé privée : {}", hex::encode(&cle.private_key));
    println!("Chain code : {}", hex::encode(&cle.chain_code));
    println!("Clé publique : {}", hex::encode(&cle.public_key()));
    println!("xprv : {}", cle.xprv());
    println!("xpub : {}", cle.xpub());
}

pub fn run() -> io::Result<()> {
    let mut seed: Option<Seed> = None;
    loop {
        println!();
        println!("=== Wallet BTC ===");
        println!("1. Générer une phrase mnémonique");
        println!("2. Importer une phrase mnémonique");
        println!("3. Afficher les clés maîtresses");
        println!("4. Dériver une clé enfant (index N)");
        println!("5. Dériver une clé enfant par chemin (niveau M)");
        println!("0. Quitter");
        let Some(choix) = lire_ligne("Choix : ")? else {
            break;
        };
        match choix.as_str() {
            "1" => seed = generer()?.or(seed),
            "2" => seed = importer()?.or(seed),
            "3" => afficher_cles_maitresses(seed.as_ref()),
            "4" | "5" => println!("Dérivation : à implémenter."),
            "0" => break,
            _ => println!("Choix invalide, réessaie."),
        }
    }
    Ok(())
}
