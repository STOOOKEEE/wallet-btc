# Wallet BTC

Projet pédagogique en Rust pour le TD « Bitcoin Wallet practice » (Blockchain Programming, révision 2025) : un wallet HD en ligne de commande qui implémente BIP39 et BIP32.

## Consignes du TD

- Un programme interactif en ligne de commande (ici en Rust).
- BIP39 : générer un aléa sûr, l'afficher en binaire/octets/hexadécimal, le découper en groupes de 11 bits, le convertir en mots, importer une phrase.
- BIP32 : clé privée maîtresse et chain code, clé publique maîtresse, clé enfant, clé enfant à l'index N, clé enfant à l'index N au niveau de dérivation M.
- Vérifier les résultats sur [Ian Coleman BIP39](https://iancoleman.io/bip39/).
- Pas de bibliothèque Bitcoin : seulement les primitives mathématiques (SHA-256, HMAC, courbe elliptique…).

## Architecture

```text
src/
├── main.rs    Point d'entrée
├── cli.rs     Menu, saisies et affichage
├── bip39.rs   Entropie, mots et seed
└── bip32.rs   Clés maîtresses et enfants
```

Les calculs restent indépendants des saisies clavier, ce qui permet de les tester avec des vecteurs de référence.

La progression est suivie dans [ROADMAP.md](ROADMAP.md).

## Lancement

Installer Rust et Cargo, puis depuis le dossier du dépôt :

```sh
cargo run
```
