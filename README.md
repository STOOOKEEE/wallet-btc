# Wallet BTC

Projet pédagogique en Rust pour le TD « Bitcoin Wallet practice » (Blockchain Programming, révision 2025) : un wallet HD en ligne de commande qui implémente BIP39 et BIP32.

## Lancement

Installer [Rust et Cargo](https://rustup.rs), puis depuis le dossier du dépôt :

```sh
cargo run      # lance le menu interactif
cargo test     # lance les tests (vecteurs officiels BIP39 et BIP32)
```

Menu :

```text
1. Générer une phrase mnémonique
2. Importer une phrase mnémonique
3. Afficher les clés maîtresses
4. Dériver une clé enfant (index N)
5. Dériver une clé enfant par chemin (niveau M)
0. Quitter
```

Après le choix `1` ou `2`, le programme demande une passphrase (Entrée pour aucune) et garde la seed en mémoire. Les choix `3`, `4` et `5` l'utilisent. Un index renforcé s'écrit `5'` (ou `5h`).

Exemple : `2`, puis `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`, Entrée, puis `5` et `m/44'/0'/0'/0/5`.

## Architecture

```text
src/
├── main.rs     Point d'entrée
├── cli.rs      Menu, saisies et affichage
├── bip39.rs    Entropie, checksum, mots, import et seed
├── bip32.rs    Clés maîtresses, dérivation des enfants, xprv/xpub
├── base58.rs   Encodage Base58Check des clés étendues
├── hex.rs      Affichage hexadécimal
└── english.txt Liste officielle BIP39 anglaise (2048 mots)
```

Les calculs sont séparés du menu, ce qui permet de les tester avec des vecteurs de référence.

Bibliothèques utilisées (primitives autorisées par le TD, aucune bibliothèque Bitcoin) :

- `getrandom` : aléa cryptographique du système ;
- `sha2`, `hmac`, `pbkdf2`, `ripemd` : fonctions de hachage ;
- `k256` : opérations sur la courbe secp256k1 (clé privée → clé publique, addition modulo n) ;
- `unicode-normalization` : normalisation NFKD demandée par BIP39.

## Rapport

### BIP39

- **Q2 – Entropie.** 16 octets (128 bits) tirés avec `getrandom`, affichés aussi comme un entier de 128 bits.
- **Q3 – Représentations.** Le programme affiche les octets, l'hexadécimal et le binaire. Le checksum correspond aux 4 premiers bits de SHA-256(entropie). Il est ajouté à la fin pour obtenir 132 bits, découpés en 12 groupes de 11 bits.
- **Q4 – Mots.** Chaque groupe de 11 bits est un indice entre 0 et 2047 dans la liste officielle.
- **Q5 – Import.** Le programme vérifie qu'il y a 12 mots, que chacun est dans la liste et que le checksum est correct. Il reconstruit ensuite l'entropie. La seed de 512 bits est obtenue avec PBKDF2-HMAC-SHA512 (2048 itérations, sel `"mnemonic" + passphrase`).

### BIP32

- **Q6 – Clé maîtresse.** On calcule `I = HMAC-SHA512("Bitcoin seed", seed)`. Les 32 premiers octets donnent la clé privée maîtresse, les 32 derniers le chain code.
- **Q7 – Clé publique maîtresse.** On calcule `K = k·G` sur secp256k1, sous forme compressée (33 octets). Le programme affiche aussi les clés étendues `xprv` / `xpub` (sérialisation BIP32 + Base58Check).
- **Q8 – Clé enfant.** CKDpriv : `I = HMAC-SHA512(chain code parent, données || index)`. Les données sont la clé publique pour un enfant normal, `0x00 || clé privée` pour un enfant renforcé (index ≥ 2^31). La clé enfant vaut `(IL + clé parent) mod n` et le chain code enfant vaut `IR`.
- **Q9 – Index N.** L'index est saisi au clavier (`5` normal, `5'` renforcé).
- **Q10 – Index N au niveau M.** Un index N et un niveau M ne suffisent pas : il faut aussi connaître les index des niveaux au-dessus. On demande donc un chemin complet, par exemple `m/44'/0'/0'/0/5` (niveau M = 5, index N = 5).

### Vérifications

- `cargo test` : 12 tests. Ils couvrent 5 vecteurs BIP39 (trezor), le vecteur de seed avec la passphrase `TREZOR`, le vecteur 1 de BIP32 (maître, `m/0'`, `m/0'/1`, `m/0'/1/2'/2/1000000000`) et le refus des saisies invalides.
- Comparaison avec [Ian Coleman BIP39](https://iancoleman.io/bip39/) sur la phrase de test `abandon … about` :

| Donnée | Résultat (identique sur les deux) |
|---|---|
| Seed (passphrase `TREZOR`) | `c55257c360c07c72…98e7463b04` |
| BIP32 Root Key (`TREZOR`) | `xprv9s21ZrQH143K3h3fDYiay8mocZ3a…KzUsAF` |
| BIP32 Root Key (sans passphrase) | `xprv9s21ZrQH143K3GJpoapnV8SFfukc…QTPvfUu` |
| xprv de `m/44'/0'/0'/0` | `xprvA1Lvv1qpvx3f8iuRHfaEG45fyvDc…N5kmFe` |
| Clé publique de `m/44'/0'/0'/0/5` | `034719fafe65dc2895e74f2a0b65f876…3552f4` |

### Limites

- La génération et l'import se limitent aux phrases de 12 mots (128 bits), en anglais.
- Seule la dérivation privée (CKDpriv) est implémentée : pas de dérivation à partir d'une xpub seule, ni de calcul d'adresses ou de transactions.
- La passphrase est saisie en clair et les espaces au début et à la fin sont supprimés.
- Les clés sont affichées en clair : à utiliser uniquement avec des phrases de test.
