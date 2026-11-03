# Plan d'implémentation : Fiabilisation de la détection des fuites e-mail & Contre-vérification HaveIBeenPwned

## 1. Contexte et Diagnostic du Problème
Lors du test de l'adresse e-mail `b_chazal@hotmail.com`, l'outil affichait 0 fuite détectée alors que le compte est répertorié dans 5 à 6 brèches majeures mondiales (*Free 2024, Collection-1, 1.4BillionRecords, ExploitIN, Adobe*).

### Cause racine identifiée :
1. Dans `server.ts`, le délai d'attente réseau (`AbortController`) vers l'API d'audit était fixé à seulement **4 000 ms** (4 secondes).
2. Lorsque la latence réseau dépassait 4 secondes, l'appel basculait silencieusement sur un repli de secours local avec `breachCount: 0`, générant un **faux négatif critique** (l'adresse apparaissait sécurisée alors qu'elle était compromise).
3. Dans `src/App.tsx`, le client reprenait ce résultat sans avertir l'utilisateur d'un dépassement de délai.

---

## 2. Solutions validées (Options 1, 2 et 3)

### Action 1 : Allongement du délai et fiabilisation de l'API (`server.ts`)
- Passer le timeout de l'appel d'audit e-mail de **4 secondes à 10 secondes** (10 000 ms) pour absorber les pics de latence des services mondiaux d'OSINT / cyber-renseignement.
- Améliorer le parsing des détails de brèches (`ExposedBreaches.breaches_details` et `BreachesSummary.site`) afin d'extraire toutes les brèches avec date, sévérité, résumé et recommandations de protection.
- Maintenir le cache ultra-rapide en mémoire (10 minutes) pour que les requêtes successives sur une même adresse répondent instantanément (< 1 ms).

### Action 2 : Règle stricte « Zéro faux négatif » (`server.ts` & `src/App.tsx`)
- **Suppression définitive du repli silencieux vers « 0 fuite » en cas d'erreur réseau.**
- Si le service d'audit mondial est indisponible ou dépasse les 10 secondes, l'application renvoie un statut d'erreur explicite :
  - Notification claire à l'écran : *"Le service d'analyse mondial n'a pas pu répondre à temps. Par sécurité, aucun résultat faux-positif ou faux-négatif n'est affiché."*
  - Bouton interactif dédié **« Réessayer l'analyse »** permettant de relancer immédiatement la requête sans ressaisir l'adresse.

### Action 3 : Bouton de contre-vérification directe HaveIBeenPwned
- Dans la section des résultats d'audit d'e-mail, intégrer un bloc distinctif et valorisant :
  - Bouton cliquable avec icône externe : **« Vérifier également sur HaveIBeenPwned.com »** (ouvrant `https://haveibeenpwned.com/` dans un nouvel onglet).
  - Note informative expliquant la complémentarité : HaveIBeenPwned nécessite un abonnement payant pour ses API e-mail automatisées, tandis que notre moteur utilise une API libre et ouverte combinée au protocole K-Anonymat pour les mots de passe.

---

## 3. Fichiers modifiés
1. **`server.ts`** :
   - Timeout étendu à 10 secondes.
   - Suppression du repli silencieux vers 0 fuite lors d'un échec réseau ; renvoi d'une erreur 504 / 502 documentée.
   - Normalisation enrichie des données de brèches retournées.
2. **`src/App.tsx`** :
   - Gestion de l'état d'erreur de timeout avec affichage d'un encart d'avertissement et bouton "Réessayer".
   - Ajout du composant de contre-vérification HaveIBeenPwned dans la carte de résultat d'audit e-mail.
3. **`tests/security.test.ts`** :
   - Mise à jour et validation des tests unitaires pour garantir la détection exacte des fuites réelles et l'absence de faux négatifs silencieux.

---

## 4. Plan de Recette & Vérification
1. **Test unitaire** : Exécution de la suite de tests automatisée (`npm test`).
2. **Compilation globale** : Validation via `compile_applet` sans aucune régression TypeScript ni build.
3. **Test fonctionnel en situation réelle** :
   - Test de `b_chazal@hotmail.com` : vérification que les 5-6 brèches s'affichent immédiatement avec leurs détails.
   - Test d'une adresse saine (ex. `contact-dsi-test-2026@sudouest.fr`) : affichage du badge vert "Aucune fuite détectée".
   - Vérification du bouton "Relancer l'audit..." et du bouton de contre-vérification HaveIBeenPwned.
