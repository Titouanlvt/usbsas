# Barbacane suite — gestion centralisée des bornes (conception)

Statut : **conception, aucun code**. Document de départ pour l'implémentation.
Barbacane v1 (borne hors ligne) reste inchangé : la « suite » est un **produit
distinct** (ISO borne en ligne + ISO serveur).

## 1. Décisions prises

| Sujet | Décision |
|---|---|
| Échelle | 10 à 100 bornes. **Un serveur unique** pour commencer ; serveur central de consolidation multi-sites prévu plus tard (§9). |
| Réseau | LAN de gestion **sans Internet**. Sites reliés par VPN site à site + VXLAN (même réseau de niveau 2). |
| Sens des connexions | **La borne appelle le serveur** ; la borne n'écoute aucun port. TLS avec authentification mutuelle (mTLS). |
| Serveur injoignable | La **borne en ligne se bloque** (message à l'écran). Les bornes v1 hors ligne ne sont pas concernées. |
| Passage v1 → en ligne | **Réinstallation obligatoire** : la v1 ne contient aucun code réseau. |
| Livraison du serveur | **ISO dédiée** (Debian durcie, installation automatique hors ligne) qui embarque les images Docker du serveur. |
| Enrôlement des bornes | **Jeton à usage unique** généré dans l'interface web. |
| Fonctions | Supervision, mises à jour centralisées, journaux et rapports, configuration et politique, gestion des clés (fabricant + numéro de série), identification des utilisateurs. |
| Identification | Méthodes au choix de l'administrateur, par site ou par borne : **comptes locaux, PIN personnel, annuaire AD/LDAP**. Badges : emplacement prévu, implémentation reportée (aucun matériel de test). |
| Données envoyées par la borne | Rapports et journaux, **fichiers malveillants et suspects** (quarantaine chiffrée). |
| Rôles web | Administrateur, administrateur de site, opérateur, auditeur (lecture seule). |
| Conservation | Journaux et rapports **1 an**, quarantaine **30 jours**, purge automatique. |
| Cadre | Recommandations **ANSSI** / homologation, **Diffusion Restreinte** (IGI 1300), **RGPD**. |
| Mises à jour | L'administrateur dépose le `.bcu` signé dans l'interface web ; le serveur le diffuse. |
| Analyse | **ClamAV et YARA restent sur la borne** : toute la décision (sain / bloqué) est prise localement, comme en v1. Le serveur ne fait que gérer, superviser et stocker. |

## 2. Principes de sécurité

1. **Un serveur compromis ne compromet pas les bornes.**
   - Le serveur ne détient jamais la clé de signature des mises à jour (elle reste hors ligne).
   - Chaque borne **revérifie elle-même** la signature et l'anti-retour arrière d'un `.bcu`, comme en v1.
   - Le serveur ne peut pas exécuter de commande sur une borne : il **publie** une politique, la borne la **récupère**, la vérifie (schéma, bornes de valeurs) et l'applique.
2. **Surface minimale de la borne** : aucun port en écoute, une seule connexion sortante vers une adresse et un port fixés (pare-feu nftables : tout le reste refusé).
3. **Identité forte de chaque borne** : certificat client propre à la borne, clé privée générée sur la borne et non exportable (TPM 2.0 si présent, sinon fichier protégé).
4. **Les identifiants USB ne prouvent rien** : fabricant (VID/PID) et numéro de série se falsifient. Ils servent à la gestion et à la traçabilité ; la décision de confiance reste l'analyse du contenu. Une clé « connue » au sens du serveur reste soumise à l'analyse.
5. **Pas de contenu sensible en clair** : fichiers en quarantaine chiffrés de bout en bout, de la borne au stockage du serveur.
6. **Traçabilité** : journal d'audit du serveur inaltérable (entrées chaînées par empreinte et signées), y compris pour les actions des administrateurs.
7. **Cœur usbsas inchangé** : l'agent réseau est un composant Barbacane séparé ; usbsas reste sans réseau.

## 3. Architecture

```
┌─────────── LAN de gestion (sans Internet), sites reliés par VPN + VXLAN ───────────┐
│                                                                                     │
│  Borne Barbacane en ligne (ISO distincte de la v1)                                  │
│   usbsas + analyseur + interface (comme v1)                                         │
│   barbacane-agent  ── connexion sortante unique, TLS 1.3, mTLS ──┐                  │
│     • récupère : politique, méthodes d'identification, clés      │                  │
│       enrôlées, mises à jour .bcu                                │                  │
│     • envoie : état, rapports, journaux, quarantaine chiffrée    │                  │
│     • serveur injoignable → borne bloquée                        │                  │
│                                                                  ▼ 443/TCP          │
│  Serveur Barbacane (ISO durcie, Docker embarqué)                                    │
│   ┌ passerelle-bornes (Rust) : seul point d'entrée des bornes, mTLS, quotas         │
│   ├ interface web d'administration : sur une INTERFACE RÉSEAU DISTINCTE (poste      │
│   │   d'administration), TLS, authentification forte, rôles                        │
│   ├ identité : comptes locaux, PIN, connecteur AD/LDAP (lecture seule)              │
│   ├ PKI interne : autorité intermédiaire en ligne ; racine HORS LIGNE               │
│   ├ diffusion des mises à jour : réception du .bcu, vérification, distribution      │
│   ├ base PostgreSQL : bornes, sites, utilisateurs, clés, politiques, rapports       │
│   ├ quarantaine chiffrée + purge à 30 jours                                         │
│   └ journal d'audit chaîné et signé                                                 │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Borne en ligne

- Même base que la v1 (usbsas, analyseur, interface, mises à jour signées).
- Nouveau service `barbacane-agent` (Rust, utilisateur dédié, durci comme les autres) :
  seul processus autorisé à joindre le réseau, et uniquement le serveur.
- L'interface ne parle qu'à l'agent local (socket Unix), jamais au réseau.
- Identification utilisateur à l'écran selon la politique reçue ; la vérification se
  fait par le serveur (le PIN ou le mot de passe ne sont jamais stockés sur la borne).
- Blocage : sans connexion valide au serveur (délai court, configurable), l'interface
  affiche « Borne hors service : serveur de gestion injoignable » et refuse toute clé.

### 3.2 Serveur

- ISO Debian durcie, installation automatique comme la borne ; images Docker chargées
  depuis l'ISO (aucun registre externe).
- Deux interfaces réseau : **bornes** (passerelle uniquement) et **administration**
  (interface web uniquement), séparées par le pare-feu.
- Conteneurs non privilégiés, systèmes de fichiers en lecture seule, secrets hors des
  images, journaux vers le journal d'audit.
- L'analyse reste sur la borne. Éventuelle analyse complémentaire des fichiers suspects (bac à sable, autres moteurs) :
  **phase ultérieure**, dans une VM séparée et non un simple conteneur.

## 4. Flux

| Flux | Sens | Contenu | Protection |
|---|---|---|---|
| Enrôlement | borne → serveur | jeton à usage unique + demande de certificat (CSR) | jeton limité dans le temps, lié à un site ; CSR signé par l'autorité intermédiaire |
| Battement | borne → serveur | état, version, âge des signatures, espace disque | mTLS |
| Politique | borne ← serveur (à l'initiative de la borne) | méthodes d'identification, clés enrôlées, règles | signée par le serveur, versionnée, validée par la borne |
| Mise à jour | borne ← serveur | `.bcu` + `.minisig` | signature hors ligne vérifiée par la borne |
| Identification | borne → serveur | identifiant + secret saisi | mTLS ; aucune conservation sur la borne |
| Rapports, journaux | borne → serveur | JSON, journald | mTLS ; file d'attente locale bornée |
| Quarantaine | borne → serveur | fichiers malveillants ou suspects | chiffrés pour la clé publique de quarantaine du serveur, puis mTLS |

## 5. Conformité

- **ANSSI** : TLS 1.3 (ou 1.2 avec suites recommandées), PKI conforme au RGS, journalisation
  selon les recommandations ANSSI, durcissement Debian (guide de configuration GNU/Linux).
- **Diffusion Restreinte** : la quarantaine peut contenir des données DR. Le serveur
  traite donc des données DR et doit être **homologué à ce niveau** ; la liaison entre
  sites peut exiger un **chiffreur agréé** (à valider avec l'autorité d'homologation,
  le VPN site à site seul peut ne pas suffire). Prévoir une option « quarantaine
  désactivée » pour les sites qui ne peuvent pas l'accepter.
- **RGPD** : registre de traitement, durées de conservation (1 an / 30 jours) appliquées
  par purge automatique, accès aux données selon les rôles, information des utilisateurs.

## 6. Analyse des risques (principales menaces)

| Menace | Mesure |
|---|---|
| Serveur compromis qui pousse du code | Aucun code poussé ; `.bcu` signés hors ligne et vérifiés par la borne. |
| Serveur compromis qui affaiblit la politique | Valeurs minimales codées en dur dans la borne (analyse toujours obligatoire, jamais de désactivation de ClamAV) ; politique signée et journalisée. |
| Usurpation d'une borne | Certificat client par borne, clé non exportable ; révocation dans l'interface web. |
| Vol du jeton d'enrôlement | Usage unique, durée courte, lié à un site, journalisé. |
| Attaque réseau sur la borne | Aucun port en écoute ; une seule destination autorisée. |
| Fausse clé « connue » (VID/PID/SN falsifiés) | Identifiants USB = traçabilité seulement ; analyse toujours obligatoire. |
| Fuite de la quarantaine | Chiffrement de bout en bout, accès réservé, purge à 30 jours. |
| Panne du serveur | Bornes bloquées par conception : procédure de reprise documentée, sauvegarde et restauration testées ; redondance prévue plus tard. |
| Administrateur malveillant | Rôles séparés, journal d'audit inaltérable consultable par l'auditeur. |

## 7. Découpage en étapes

1. **Socle** : ISO serveur (Debian durcie + Docker embarqué), PKI interne, passerelle
   mTLS, enrôlement par jeton, battement et supervision dans l'interface web.
2. **Mises à jour** : dépôt du `.bcu` dans l'interface web, diffusion, suivi par borne.
3. **Rapports et journaux** : collecte, recherche, export, conservation 1 an.
4. **Identification** : comptes locaux et PIN, puis AD/LDAP ; choix par site ou par borne.
5. **Clés USB** : enrôlement par fabricant + numéro de série, politiques par site.
6. **Quarantaine** chiffrée, purge 30 jours, option de désactivation.
7. **Plus tard** : badges, analyse complémentaire en bac à sable, serveur central de
   consolidation multi-sites, redondance.

Chaque étape : conception détaillée, tests automatisés, preuves, CI verte.

## 8. Questions ouvertes

- Type de badges (reporté faute de matériel) : prévoir une interface d'identification
  extensible.
- Exigences exactes de l'autorité d'homologation (chiffreur, produits qualifiés).
- Où conserver la racine de la PKI (support hors ligne, coffre) et qui la détient.
- Durée de blocage acceptable : délai de grâce de quelques minutes après une coupure
  réseau courte, ou blocage immédiat ?

## 9. Évolution prévue : serveur central

Plus tard, un serveur central consolidera plusieurs serveurs de site par le VPN
site à site. Rôle à définir (consolidation seule recommandée : chaque site reste maître
de ses bornes). Les choix de l'étape 1 (identifiants uniques de site, PKI hiérarchique)
doivent le permettre sans refonte.
