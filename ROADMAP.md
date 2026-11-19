# Roadmap du projet Wallet BTC

Une branche fusionnée par merge commit par partie du TD, un commit par question.

- [x] **Q1. Menu interactif.** Générer, importer, afficher les clés, dériver, quitter. Entrées invalides et fin de saisie gérées.
- [x] **Q2. Entropie.** 128 bits tirés de l'aléa cryptographique du système.
- [x] **Q3. Représentations.** Octets, hexadécimal, binaire, checksum SHA-256 et groupes de 11 bits.
- [x] **Q4. Phrase BIP39.** Liste officielle anglaise, conversion des indices en mots.
- [x] **Q5. Import d'une phrase.** Vérifier les mots, la longueur et le checksum, puis calculer la seed (PBKDF2-HMAC-SHA512, 2048 itérations, passphrase facultative).
- [x] **Q6. Clé privée maîtresse et chain code.** HMAC-SHA512 de la seed avec la clé « Bitcoin seed ».
- [ ] **Q7. Clé publique maîtresse.** Multiplication sur secp256k1, forme compressée.
- [ ] **Q8. Clé enfant.** Dérivation CKDpriv d'un enfant.
- [ ] **Q9. Clé enfant à l'index N.** Index normal ou renforcé.
- [ ] **Q10. Clé enfant à l'index N au niveau M.** Chemin complet, par exemple `m/44'/0'/0'/0/5`.
- [ ] **Rapport.** Vérification avec Ian Coleman, instructions et rapport dans le README.
