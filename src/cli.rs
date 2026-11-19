//! Menu interactif, saisies et affichage.
use std::io::{self, Write};

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
            "1" => println!("Génération : à implémenter."),
            "2" => println!("Import : à implémenter."),
            "3" => println!("Affichage des clés : à implémenter."),
            "4" | "5" => println!("Dérivation : à implémenter."),
            "0" => break,
            _ => println!("Choix invalide, réessaie."),
        }
    }
    Ok(())
}
