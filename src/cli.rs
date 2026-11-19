//! Menu interactif, saisies et affichage.
use std::io::{self, Write};

use crate::bip39;

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

/// Représentation hexadécimale d'une suite d'octets.
fn hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

fn generer() {
    let entropy = match bip39::generate_entropy() {
        Ok(entropy) => entropy,
        Err(erreur) => {
            println!("Erreur de génération : {erreur}");
            return;
        }
    };
    println!("Entropie (entier 128 bits) : {}", u128::from_be_bytes(entropy));
    afficher_representations(&entropy);
    println!("Phrase BIP39 : {}", bip39::mnemonic(&entropy));
}

fn afficher_representations(entropy: &[u8; bip39::ENTROPY_BYTES]) {
    println!("Octets : {entropy:?}");
    println!("Hexadécimal : {}", hex(entropy));
    println!("Checksum (4 bits) : {:04b}", bip39::checksum(entropy));
    println!("Binaire + checksum : {}", bip39::bits_with_checksum(entropy));
    println!("Groupes de 11 bits → indice :");
    for index in bip39::word_indices(entropy) {
        println!("  {index:011b} → {index}");
    }
}

pub fn run() -> io::Result<()> {
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
            "1" => generer(),
            "2" => println!("Import : à implémenter."),
            "3" => println!("Affichage des clés : à implémenter."),
            "4" | "5" => println!("Dérivation : à implémenter."),
            "0" => break,
            _ => println!("Choix invalide, réessaie."),
        }
    }
    Ok(())
}
