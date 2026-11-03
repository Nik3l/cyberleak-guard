# cyberleak-guard
Site pour voir si une adresse email, un mot de passe ou le combat a été trouvé dans une fuite de données


Source de données pour les adresses e-mail : L'API locale interroge en temps réel les bases réelles de fuites mondiales.
Corrélation du Combo (E-mail + Mot de passe) : 
Intégration d'un flux en direct de renseignement sur les menaces :
L'analyse d'adresse e-mail interroge désormais les registres publics mondiaux réels de violations de données (regroupant plus de 14 milliards de comptes issus de fuites comme Dropbox, Deezer, LinkedIn, PeopleDataLabs, MyFitnessPal, Dailymotion, COMB, etc.).
Si l'adresse a fuité, l'application liste le nom exact des brèches, l'année, les données précises compromises (mots de passe, numéros de téléphone, adresses IP, identifiants) et le nombre de comptes affectés.
Audit Combo intelligent (E-mail + Mot de passe) :
Vérification simultanée de l'e-mail (dans les fuites réelles) et du mot de passe (via le protocole cryptographique k-Anonymat SHA-1 sans jamais exposer le mot de passe en clair).
Évaluation dynamique du risque de Credential Stuffing :
Critique si l'adresse ET ce mot de passe sont tous deux dans des fuites publiques.
Modéré / Rassurant si l'adresse e-mail a fuité par le passé mais que le mot de passe testé est 100 % sain (0 occurrence k-anonymat).
Sécurisé si aucun des deux n'est recensé.
Expérience utilisateur renforcée :
Indicateur d'état en direct pendant l'analyse (calcul SHA-1, interrogation de la base mondiale).
Remise à zéro automatique des résultats à chaque nouveau scan ou changement de mode.
Gestion des erreurs et validation du format de l'e-mail.
flag

L’application est conçue pour être 100 % opérationnelle immédiatement, sans abonnement, sans compte à créer et sans clé payante.
Comment le site fonctionne-t-il sans clé ?
Vérification des Mots de passe (k-Anonymat) :
Utilise l'API publique ouverte de référence HaveIBeenPwned Pwned Passwords (api.pwnedpasswords.com).
Cette API est gratuite et libre d'accès.
Grâce au protocole cryptographique de k-Anonymat, seuls les 5 premiers caractères du hash SHA-1 sont transmis, sans nécessiter d'authentification par clé API.
Vérification des Adresses E-mail & Violations de données :
Interroge en temps réel le registre public ouvert de renseignement sur les cybermenaces (XposedOrNot), regroupant plus de 14 milliards de comptes exposés (Dropbox, LinkedIn, Deezer, etc.).
Ne nécessite aucune clé d'accès et dispose d'un cache mémoire rapide pour éviter toute limitation.
Dispose d'une base de secours locale (fallback) intégrée pour continuer à répondre même en cas de coupure réseau externe.
Vérification du Combo, Générateur & Checklist DSI :
L'évaluation des risques de credential stuffing, le calcul d'entropie, la génération de mots de passe et le plan de remédiation sont exécutés directement sur le serveur et le navigateur.
(Note : Une variable optionnelle HIBP_API_KEY figure dans .env.example uniquement si une entreprise souhaite un jour brancher sa propre licence payante d'entreprise HaveIBeenPwned, mais pour le fonctionnement actuel, vous n'en avez absolument pas besoin).
lightbulb_tips