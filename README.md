# Proxmox VM Security

Projet de sécurisation d'une infrastructure virtualisée sous **Proxmox** : durcissement système, segmentation réseau et cryptographie appliquée, à travers trois modules complémentaires qui font évoluer une même infrastructure de machines virtuelles étape par étape.

## Contexte

Projet académique réalisé dans le cadre de la matière **SR06** (filière **GI04**, UTC). Chaque module correspond à un rendu noté distinct ; les README de ce dépôt détaillent l'objectif de chaque module et ce qui a été concrètement réalisé, d'après les notes de travail du binôme (anonymisées avant publication — voir la section [Anonymisation](#anonymisation)).

## Architecture globale

L'infrastructure se construit progressivement sur les 3 modules, en réutilisant et en complétant les VM des étapes précédentes plutôt qu'en repartant de zéro :

- **Module 1 (Risque)** : deux VM, `vm-cli` et `vm-web`, clonées d'un template volontairement vulnérable (`vm-passoire`), durcies (comptes, permissions, services réseau) et dotées d'un serveur Apache/PHP sur `vm-web` avec séparation des rôles (`publie`, `edite`, `controle` en cage chroot).
- **Module 2 (Protection réseau)** : l'infrastructure passe à 5 VM réparties sur 4 zones réseau — **LAN** (`vm-lan`), **INTERNET** (`vm-int`), **WEB** (`vm-web`, DMZ) et **SQL** (`vm-sql`, DMZ) — reliées par un routeur (`vm-router`) qui filtre et cloisonne le trafic entre zones (iptables, NAT/DNAT, protection anti SYN-Flood et anti scan de ports). `vm-web` est réutilisée depuis le module 1 ; une application web 3 tiers (présentation / PHP / MariaDB sur `vm-sql`) est ajoutée, déclinée en version vulnérable et sécurisée.
- **Module 3 (Cryptographie)** : `vm-web` est complétée par un chiffrement LUKS de son `/home`, une authentification SSH par clé pour les comptes `edite`/`publie`, un passage en HTTPS et une architecture PKI à 3 niveaux (Root CA → Policy CA → Server/Client CA, gérée avec XCA) pour l'authentification serveur et client, avec contrôle de révocation (CRL).

Le détail des adresses IP, règles de filtrage et commandes exactes se trouve dans le README de chaque module.

## Les 3 modules

### [Module 1 — Sécurité et durcissement Linux (Risque)](module-1-risque/README.md)
Durcissement de deux VM clonées d'un template vulnérable : gestion des comptes et des mots de passe, permissions (setuid, sticky bit), services réseau minimaux, et sur `vm-web` un serveur Apache/PHP avec séparation stricte des rôles d'administration (comptes dédiés, dont un isolé en cage chroot) et un stockage `/var`/`/home` déplacé sur une partition dédiée avec options de montage restrictives.

### [Module 2 — Protection réseau](module-2-protection-reseau/README.md)
Segmentation de l'infrastructure en 4 zones réseau reliées par un routeur filtrant, avec une politique par défaut restrictive (tout est bloqué sauf ce qui est explicitement autorisé). Application web 3 tiers connectée à une base MariaDB, déclinée en version vulnérable et sécurisée. Protections actives contre le SYN-Flood et le scan de ports, exposition contrôlée du service web vers Internet via NAT, et serveur DNS interne en option.

### [Module 3 — Cryptographie](module-3-cryptographie/README.md)
Protection des données au repos et des échanges : chiffrement LUKS du `/home` de `vm-web`, authentification SSH par clé, passage du serveur web en HTTPS, et déploiement d'une PKI complète à 3 niveaux avec XCA pour l'authentification mutuelle client/serveur et la gestion de la révocation de certificats (CRL).

## Compétences démontrées

- **Durcissement système Linux** : gestion des comptes et permissions, bits setuid/sticky, umask restrictif, isolation par cage chroot, principe de moindre privilège.
- **Sécurité des accès** : authentification SSH par clé (remplacement du mot de passe), séparation des rôles via `sudo`/groupes dédiés, protection anti force brute (fail2ban).
- **Filtrage et segmentation réseau** : conception et écriture de règles `iptables` (filtrage, NAT/DNAT, MASQUERADE), architecture en zones de confiance (LAN/DMZ/Internet), politique de sécurité par défaut restrictive.
- **Protection contre les attaques réseau courantes** : SYN-Flood (SYN cookies + limitation de débit), scans de ports (NULL/XMAS/FIN), injection SQL (comparaison version vulnérable / sécurisée).
- **Cryptographie appliquée** : chiffrement de disque (LUKS), TLS/HTTPS, conception d'une PKI hiérarchique à 3 niveaux avec XCA (profils de certificat, Key Usage/Extended Key Usage, chaînes de confiance), authentification mutuelle client/serveur, gestion de la révocation (CRL).
- **Gestion des risques** : analyse d'une architecture volontairement vulnérable et correction méthodique des failles identifiées, documentation explicite des parties non traitées plutôt que du contournement silencieux.

## Limites connues

Chaque module documente explicitement, dans son propre README, les objectifs non traités ou non détaillés dans les notes de travail — listés ici en résumé, avec renvoi vers le détail :

- **Module 1** : suppression nominative des comptes de TD et correction spécifique du compte `etu` non détaillées ; le formulaire PHP de saisie/stockage de noms n'est pas développé (seul un fichier de test existe) ; prise d'un snapshot avant l'ajout du disque non confirmée. *(→ [détail](module-1-risque/README.md))*
- **Module 2** : clonage/renommage explicite des 5 VM et compte dédié phpMyAdmin non détaillés ; la version **sécurisée** de l'application web (protection anti-injection SQL) n'est pas développée, seul le dossier existe ; l'analyse optionnelle avec `phpcs`/`nikto` n'a pas été réalisée. *(→ [détail](module-2-protection-reseau/README.md))*
- **Module 3** : la partie **Signature** n'est pas traitée (document signé par `edite` via la PKI puis publié) — et par conséquent, sa vérification finale non plus ; le test explicite du rejet d'un certificat révoqué n'est pas confirmé, seule sa configuration l'est. *(→ [détail](module-3-cryptographie/README.md))*

## Anonymisation

Les notes de travail originales contenaient des données identifiantes (adresses IP réelles de l'infrastructure UTC, identifiants de compte, noms de machines personnels, mots de passe d'exemple). Elles ont été remplacées par des valeurs neutres avant publication ; certaines captures d'écran jugées sensibles (interface Proxmox du cluster réel, identifiants visibles à l'écran) ont été retirées ou remplacées par un bandeau explicatif.
