export interface DataBreach {
  id: string;
  name: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isFabricated: boolean;
  isSensitive: boolean;
  isSpamList: boolean;
  category: 'Tech' | 'Social' | 'Entertainment' | 'Finance' | 'Retail' | 'Gaming' | 'StealerLogs' | 'ComboList';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  remediationAdvice: string;
}

export const KNOWN_BREACHES: DataBreach[] = [
  {
    id: 'naz-api',
    name: 'Naz.API & Stealer Logs',
    domain: 'illicit.services',
    breachDate: '2024-01-16',
    addedDate: '2024-01-18',
    pwnCount: 70845320,
    description: 'Une compilation massive de 71 millions d\'identifiants extraits de journaux de malwares de type "Info-stealers" (RedLine, Vidar, Racoon) et de listes combinées.',
    dataClasses: ['Email addresses', 'Passwords', 'Browser Cookies', 'Operating System details'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'StealerLogs',
    severity: 'Critical',
    remediationAdvice: 'Scannez votre ordinateur avec un antivirus moderne, révoquez les sessions de navigateur actives et changez impérativement tous vos mots de passe.'
  },
  {
    id: 'comb-3b',
    name: 'COMB (Compilation of Many Breaches)',
    domain: 'darkweb-archive.org',
    breachDate: '2021-02-02',
    addedDate: '2021-02-05',
    pwnCount: 3270000000,
    description: 'La plus grande compilation d\'identifiants jamais assemblée sur le dark web, regroupant plus de 3,2 milliards de couples email/mot de passe en texte clair provenant de multiples brèches historiques.',
    dataClasses: ['Email addresses', 'Passwords', 'Plaintext credentials'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'ComboList',
    severity: 'Critical',
    remediationAdvice: 'Activez l\'authentification à deux facteurs (2FA) sur tous vos comptes critiques et n\'utilisez jamais le même mot de passe sur deux services.'
  },
  {
    id: 'collection-1',
    name: 'Collection #1 - #5',
    domain: 'mega.nz',
    breachDate: '2019-01-07',
    addedDate: '2019-01-17',
    pwnCount: 772904991,
    description: 'Une archive gigantesque de 87 Go contenant plus de 770 millions d\'adresses e-mail uniques et 21 millions de mots de passe déhashés circulant sur les forums cybercriminels.',
    dataClasses: ['Email addresses', 'Passwords'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'ComboList',
    severity: 'Critical',
    remediationAdvice: 'Ne réutilisez aucun mot de passe créé avant 2020. Utilisez un gestionnaire de mots de passe pour générer des clés de 16+ caractères.'
  },
  {
    id: 'deezer',
    name: 'Deezer Data Leak',
    domain: 'deezer.com',
    breachDate: '2022-11-06',
    addedDate: '2023-01-02',
    pwnCount: 228900000,
    description: 'Une fuite de données d\'un ancien partenaire tiers de Deezer a exposé les données personnelles de plus de 228 millions d\'utilisateurs, dont une grande proportion en France.',
    dataClasses: ['Email addresses', 'Dates of birth', 'IP addresses', 'Names', 'Genders', 'Spoken languages', 'Geographic locations'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Entertainment',
    severity: 'High',
    remediationAdvice: 'Méfiez-vous des e-mails et SMS d\'hameçonnage (phishing) usurpant Deezer ou vos services de streaming musical.'
  },
  {
    id: 'linkedin',
    name: 'LinkedIn Scraping & Breaches',
    domain: 'linkedin.com',
    breachDate: '2021-04-08',
    addedDate: '2021-04-12',
    pwnCount: 500000000,
    description: 'Des données extraites de 500 millions de profils LinkedIn ont été mises en vente sur un forum de hackers, combinées avec d\'autres bases professionnelles.',
    dataClasses: ['Email addresses', 'Full names', 'Phone numbers', 'Workplace details', 'Professional titles'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Social',
    severity: 'Medium',
    remediationAdvice: 'Attention aux attaques de spear-phishing professionnel et aux faux recruteurs sur LinkedIn et par e-mail.'
  },
  {
    id: 'twitter-200m',
    name: 'Twitter / X API Scraping',
    domain: 'x.com',
    breachDate: '2023-01-04',
    addedDate: '2023-01-06',
    pwnCount: 211522844,
    description: 'Une exploitation d\'une vulnérabilité d\'API début 2022 a permis la collecte et la publication de 200 millions d\'adresses e-mail associées à des identifiants Twitter.',
    dataClasses: ['Email addresses', 'Usernames', 'Follower counts', 'Account creation dates'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Social',
    severity: 'High',
    remediationAdvice: 'Vérifiez les paramètres de sécurité de votre compte X (Twitter) et activez les clés de sécurité physiques ou TOTP pour le 2FA.'
  },
  {
    id: 'canva',
    name: 'Canva Security Breach',
    domain: 'canva.com',
    breachDate: '2019-05-24',
    addedDate: '2019-06-01',
    pwnCount: 137456780,
    description: 'Le service de conception graphique australien Canva a subi une intrusion compromise par le pirate Gnosticplayers, exposant près de 140 millions de comptes.',
    dataClasses: ['Email addresses', 'Passwords', 'Customer names', 'Cities of residence', 'Salted bcrypt password hashes'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Tech',
    severity: 'High',
    remediationAdvice: 'Changez votre mot de passe Canva et tout autre compte qui utilisait la même combinaison.'
  },
  {
    id: 'adobe',
    name: 'Adobe Systems Breach',
    domain: 'adobe.com',
    breachDate: '2013-10-04',
    addedDate: '2013-11-01',
    pwnCount: 152989505,
    description: 'Une des plus célèbres brèches de l\'histoire numérique : 153 millions de comptes Adobe ont été volés avec des indices de mot de passe en clair.',
    dataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Tech',
    severity: 'High',
    remediationAdvice: 'Assurez-vous de n\'utiliser aucun ancien mot de passe datant de cette période.'
  },
  {
    id: 'facebook-533m',
    name: 'Facebook Data Leak (533M)',
    domain: 'facebook.com',
    breachDate: '2019-08-01',
    addedDate: '2021-04-03',
    pwnCount: 533313128,
    description: 'Plus de 533 millions d\'utilisateurs de 106 pays (dont près de 20 millions en France) ont vu leurs numéros de téléphone et profils Facebook divulgués.',
    dataClasses: ['Phone numbers', 'Email addresses', 'Facebook IDs', 'Full names', 'Locations', 'Birthdates', 'Bio'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Social',
    severity: 'High',
    remediationAdvice: 'Restez vigilant face au SIM-swapping et aux tentatives de smishing (SMS frauduleux).'
  },
  {
    id: 'france-travail',
    name: 'France Travail (Pôle Emploi)',
    domain: 'francetravail.fr',
    breachDate: '2024-03-08',
    addedDate: '2024-03-12',
    pwnCount: 43000000,
    description: 'Cyberattaque majeure ayant visé France Travail et Cap Emploi, exposant les données personnelles d\'environ 43 millions d\'usagers français inscrits au cours des 20 dernières années.',
    dataClasses: ['Nom et prénom', 'Numéro de sécurité sociale (NIR)', 'Identifiant France Travail', 'Adresses e-mail', 'Adresses postales', 'Numéros de téléphone'],
    isVerified: true,
    isFabricated: false,
    isSensitive: true,
    isSpamList: false,
    category: 'Finance',
    severity: 'Critical',
    remediationAdvice: 'Surveillez vos relevés bancaires et soyez extrêmement méfiant face aux démarches administratives téléphoniques sollicitant vos identifiants bancaires.'
  },
  {
    id: 'voyageurs-sncf',
    name: 'SNCF Connect / Voyageurs',
    domain: 'sncf-connect.com',
    breachDate: '2023-09-15',
    addedDate: '2023-09-20',
    pwnCount: 850000,
    description: 'Attaque par bourrage d\'identifiants (credential stuffing) contre l\'application ferroviaire française ciblant des comptes utilisateurs.',
    dataClasses: ['Email addresses', 'Loyalty card numbers', 'Travel itineraries'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Retail',
    severity: 'Medium',
    remediationAdvice: 'Ne réutilisez jamais vos identifiants de voyage ou de fidélité sur d\'autres sites.'
  },
  {
    id: 'twitch',
    name: 'Twitch Source Code & Payouts',
    domain: 'twitch.tv',
    breachDate: '2021-10-06',
    addedDate: '2021-10-08',
    pwnCount: 125000000,
    description: 'Une faille de configuration de serveur a entraîné la fuite de 125 Go de données, incluant le code source de Twitch et les paiements versés aux créateurs.',
    dataClasses: ['Email addresses', 'Usernames', 'Streaming keys', 'Payout records'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Gaming',
    severity: 'High',
    remediationAdvice: 'Réinitialisez votre clé de stream et changez votre mot de passe avec 2FA par application d\'authentification.'
  },
  {
    id: 'wattpad',
    name: 'Wattpad Data Breach',
    domain: 'wattpad.com',
    breachDate: '2020-06-29',
    addedDate: '2020-07-20',
    pwnCount: 268750800,
    description: 'La plateforme de lecture en ligne a subi une violation massive vendue sur le darknet pour plus de 100 000 dollars en cryptomonnaies.',
    dataClasses: ['Email addresses', 'Passwords', 'Dates of birth', 'IP addresses', 'Usernames'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'Entertainment',
    severity: 'High',
    remediationAdvice: 'Vérifiez si l\'adresse e-mail utilisée sur Wattpad sert à d\'autres services personnels.'
  },
  {
    id: 'roblox-dev',
    name: 'Roblox Developer Portal',
    domain: 'roblox.com',
    breachDate: '2023-07-18',
    addedDate: '2023-07-22',
    pwnCount: 3943,
    description: 'Fuite ciblant les participants aux conférences de développeurs Roblox, diffusant des informations nominatives sensibles.',
    dataClasses: ['Email addresses', 'Full names', 'Phone numbers', 'Physical addresses', 'T-shirt sizes', 'Dates of birth'],
    isVerified: true,
    isFabricated: false,
    isSensitive: true,
    isSpamList: false,
    category: 'Gaming',
    severity: 'Medium',
    remediationAdvice: 'Soyez vigilant aux approches directes sur les messageries privées Discord ou Telegram.'
  },
  {
    id: '1-4billionrecords',
    name: '1.4BillionRecords (4iQ Database)',
    domain: '4iq.com',
    breachDate: '2017-03-01',
    addedDate: '2023-11-08',
    pwnCount: 1114303554,
    description: '4iQ a découvert une gigantesque collection d\'identifiants compilée sur le dark web contenant plus de 1,4 milliard de couples identifiants/mots de passe agrégés depuis de multiples brèches antérieures.',
    dataClasses: ['Email addresses', 'Passwords', 'Names', 'IP addresses'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'ComboList',
    severity: 'Critical',
    remediationAdvice: 'Cette archive majeure circule auprès de tous les groupes cybercriminels. Remplacez impérativement tout mot de passe créé avant 2018.'
  },
  {
    id: 'free',
    name: 'Free (Iliad - Cyberattaque Octobre 2024)',
    domain: 'free.fr',
    breachDate: '2024-10-01',
    addedDate: '2024-10-22',
    pwnCount: 14247989,
    description: 'En octobre 2024, l\'opérateur Free a subi une fuite de données massive affectant 14,2 millions d\'abonnés, exposant des données d\'identité, adresses postales, numéros de téléphone et IBAN pour des millions d\'utilisateurs.',
    dataClasses: ['Email addresses', 'Names', 'Phone numbers', 'Physical addresses', 'Dates of birth', 'Bank account numbers / IBAN'],
    isVerified: true,
    isFabricated: false,
    isSensitive: true,
    isSpamList: false,
    category: 'Tech',
    severity: 'High',
    remediationAdvice: 'Coordonnées et IBAN potentiellement exposés : surveillez vos relevés bancaires et méfiez-vous des faux conseillers bancaires par téléphone.'
  },
  {
    id: 'exploitin',
    name: 'Exploit.IN',
    domain: 'exploit.in',
    breachDate: '2016-10-01',
    addedDate: '2023-11-08',
    pwnCount: 592919058,
    description: 'Le forum clandestin Exploit.IN a été piraté en 2016, entraînant la fuite de 593 millions de comptes avec identifiants, e-mails et mots de passe hashés.',
    dataClasses: ['Email addresses', 'Passwords', 'Usernames'],
    isVerified: true,
    isFabricated: false,
    isSensitive: false,
    isSpamList: false,
    category: 'ComboList',
    severity: 'Critical',
    remediationAdvice: 'URGENT : Des mots de passe ont fuité dans cette brèche. Changez immédiatement ce mot de passe partout où il a pu être réutilisé.'
  }
];

export interface ThreatStats {
  totalBreachedAccounts: number;
  monitoredBreachesCount: number;
  lastUpdated: string;
  stealerLogsCount: number;
  topPasswordsLeaked: { rank: number; password: string; count: number }[];
  compromisedDataTypes: { name: string; percentage: number; count: string }[];
}

export const CURRENT_STATS: ThreatStats = {
  totalBreachedAccounts: 14920400000,
  monitoredBreachesCount: 840,
  lastUpdated: '2026-10-31',
  stealerLogsCount: 184500000,
  topPasswordsLeaked: [
    { rank: 1, password: '123456', count: 48200000 },
    { rank: 2, password: 'password', count: 35100000 },
    { rank: 3, password: '123456789', count: 28400000 },
    { rank: 4, password: 'guest', count: 19800000 },
    { rank: 5, password: 'qwerty', count: 18200000 },
    { rank: 6, password: 'password123', count: 14700000 },
    { rank: 7, password: '111111', count: 12900000 },
    { rank: 8, password: 'admin', count: 11500000 }
  ],
  compromisedDataTypes: [
    { name: 'Adresses E-mail', percentage: 92, count: '13.7 Md' },
    { name: 'Mots de passe hashés/en clair', percentage: 78, count: '11.6 Md' },
    { name: 'Noms & Prénoms', percentage: 61, count: '9.1 Md' },
    { name: 'Numéros de Téléphone', percentage: 44, count: '6.5 Md' },
    { name: 'Adresses IP & Géolocalisation', percentage: 38, count: '5.6 Md' },
    { name: 'Données Bancaires / Financières', percentage: 14, count: '2.1 Md' }
  ]
};
