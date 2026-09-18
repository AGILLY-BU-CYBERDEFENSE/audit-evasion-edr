# Audit du socle Windows face aux vecteurs d'évasion EDR

**Dépôt de référence : <https://github.com/AGILLY-BU-CYBERDEFENSE/audit-evasion-edr>** — seule source de diffusion. Toute copie obtenue
ailleurs doit être vérifiée contre les empreintes publiées plus bas.

Script PowerShell d'audit **en lecture seule** publié par AGILLY Cyberdéfense. Il mesure le
durcissement d'un poste Windows au regard des **conditions préalables** qu'exploitent les techniques
de neutralisation d'agent EDR : privilèges d'administration locale, chargement d'un pilote dans le
noyau, absence de politique d'intégrité du code, arrêt d'un service de sécurité, absence de
télémétrie transmise à un tiers.

**Ce que l'outil ne fait pas.** Il ne teste pas la résistance effective d'un agent : une machine
conforme à l'ensemble des contrôles peut voir son agent neutralisé. Établir cette résistance relève
d'un test contrôlé en environnement isolé, qui est un exercice distinct. Chaque contrôle lit l'état de
la machine par les interfaces que Windows lui-même expose — registre, WMI, gestionnaire de services,
journaux d'événements, variables de firmware relayées par le noyau : c'est le système audité qui rend
son propre verdict. Cela vaut a fortiori pour les contrôles d'intégrité noyau, dont l'état est rapporté
à travers le noyau lui-même : un attaquant qui le contrôle peut le faire répondre « actif ». L'outil
répond à « mon socle est-il durci ? », jamais à « ai-je été compromis ? ».

Document d'accompagnement : *Vecteurs d'Évasion EDR & Architecture de Durcissement* (note technique
d'ingénierie AGILLY) — lien dans la section [Documentation](#documentation).

---

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `Audit-SocleEvasionEDR-v1.ps1` | Script d'audit, à exécuter sur le poste à évaluer |
| `AGILLY_LOLDrivers_Empreintes.csv` | Référentiel d'empreintes de pilotes vulnérables consommé par l'audit |
| `AGILLY_LOLDrivers_Empreintes.csv.sha256` | Empreinte du référentiel, pour vérification d'intégrité |
| `.gitattributes` | Interdit à Git toute normalisation des fichiers dont l'empreinte est publiée |
| `NOTICE` | Attribution des sources amont |
| `LICENSE` | Apache 2.0 |
| `docs/` | Note technique d'ingénierie, en PDF et en HTML |

## Prérequis

- Windows 10 / Windows Server 2016 ou ultérieur
- PowerShell 5.1, **console 64 bits** (une console 32 bits sur un OS 64 bits fausse l'inventaire des pilotes ; le script le détecte et le signale)
- **Session élevée** : sans élévation, une partie des contrôles sort en `INDÉTERMINÉ` et l'audit est déclaré non concluant
- Durée : moins d'une minute, plus 20 à 60 secondes pour l'inventaire des pilotes noyau

## Exécution

Deux modes équivalents.

```powershell
# 1. Coller l'intégralité du script dans une console PowerShell élevée.

# 2. Ou exécuter le fichier :
powershell -ExecutionPolicy Bypass -File .\Audit-SocleEvasionEDR-v1.ps1
```

Placer `AGILLY_LOLDrivers_Empreintes.csv` **dans le même dossier** que le script : il est détecté
automatiquement. Sans lui, la correspondance d'empreintes sort en `INDÉTERMINÉ` — les autres
contrôles sont inchangés.

Si le fichier `AGILLY_LOLDrivers_Empreintes.csv.sha256` se trouve à côté de la liste, le script
**reprend l'empreinte attendue tout seul** et vérifie la liste avant usage ; le rapport indique alors
« empreinte vérifiée ». Cette vérification atteste que la liste n'a pas été tronquée ni corrompue au
transport — elle n'atteste pas son authenticité, puisque qui remplace le CSV remplace aussi le
`.sha256` posé à côté. Pour une vérification d'authenticité, comparer à la main avec l'empreinte
publiée ci-dessus, ou imposer la valeur via `AGILLY_LOLSHA256`.

En mode collage dans une console, le dossier du script n'est pas connu : le CSV est cherché dans le
répertoire courant. Faire un `cd` dans le dossier de la liste avant de coller, ou renseigner
`$LolDriversPath`.

Avant exécution, vérifier l'intégrité des fichiers téléchargés :

```powershell
Get-FileHash .\Audit-SocleEvasionEDR-v1.ps1 -Algorithm SHA256
Get-FileHash .\AGILLY_LOLDrivers_Empreintes.csv -Algorithm SHA256   # comparer au .sha256 fourni
```

Récupération par clonage, qui préserve l'encodage grâce à `.gitattributes` :

```bash
git clone https://github.com/AGILLY-BU-CYBERDEFENSE/audit-evasion-edr
```

Le téléchargement de l'archive ZIP depuis l'interface web est déconseillé pour ces deux fichiers :
il peut normaliser les fins de ligne et rendre la vérification d'empreinte impossible.

| Fichier | SHA256 |
|---|---|
| `Audit-SocleEvasionEDR-v1.ps1` | `1651af4b6f857258d7dc6ff10b4724f7696c85a195f004a27e7a2adffda40f92` |
| `AGILLY_LOLDrivers_Empreintes.csv` | `8068aba6cd9167a898f530f2d5212be0a7bc0290b0320e33cb76b673075b0c2c` |

Le script et le référentiel sont publiés en **UTF-8 avec BOM et fins de ligne CRLF**, et
`.gitattributes` interdit toute normalisation par Git : sans cela, une conversion de fins de ligne à
l'extraction changerait l'empreinte calculée par l'utilisateur et rendrait la vérification impossible.
**Toute modification du script impose de régénérer les empreintes ci-dessus et celles citées dans la
note technique.**

## Livrables produits

- un **rapport HTML autonome** (styles embarqués, feuille d'impression : Ctrl+P donne un PDF propre) ;
- un **export CSV** pour consolidation de parc.

Destination par défaut, dans cet ordre : `Bureau\AGILLY-Audits`, `Documents\AGILLY-Audits`,
`%TEMP%\AGILLY-Audits`, `%PUBLIC%\AGILLY-Audits`. Le chemin est affiché en fin d'exécution.

## Innocuité

- Lecture seule du système : aucune clé de registre, aucun service, aucune politique n'est modifié.
- Aucune préférence de session PowerShell n'est altérée.
- **Aucun appel réseau. Aucune donnée ne quitte la machine.** Les seules écritures sont les livrables,
  dans le profil utilisateur.
- Le script est lisible : il peut être relu intégralement avant toute exécution.

> **Si votre EDR remonte une alerte pendant l'exécution**, c'est attendu et sain : le script énumère
> les pilotes noyau chargés et calcule leurs empreintes, un comportement légitimement surveillé.
> Aucun binaire n'est déposé, aucun pilote n'est chargé, aucune connexion n'est ouverte.

## Lecture des résultats

**Verdicts.** `CONFORME`, `CONFORME (PRÉSUMÉ)`, `NON CONFORME`, `INDÉTERMINÉ`, `NON APPLICABLE`,
`CONFIGURÉ (NON ACTIF)`, `INFORMATION`, `À VÉRIFIER EN CONSOLE`, `À TRIER`.

`À VÉRIFIER EN CONSOLE` désigne un point qui ne peut être tranché que depuis la console de l'éditeur.
Il ne pénalise ni le score ni la couverture : un poste sous agent tiers n'est pas artificiellement
dégradé par rapport à un poste sous Defender for Endpoint.

`À TRIER` désigne un signal d'historique — un arrêt de service, un refus de chargement, un journal
effacé. Interpréter ces événements suppose de les rapprocher des fenêtres de maintenance déclarées et
du cycle de mise à jour des agents, informations dont l'audit ne dispose pas : un agent qui redémarre
soixante fois décrit la stabilité d'un produit, trois agents distincts arrêtés dans la même heure
décrivent autre chose. **Ces constats sont restitués mais ne pèsent ni sur le score, ni sur le
plafonnement, ni sur la couverture** : faire chuter une note sur un fait que les données ne
permettent pas d'établir reviendrait à rendre un verdict non fondé. Ils ne modifient pas non plus le
code de sortie — en consolidation de parc, lire la colonne `Etat` de l'export pour les recenser.

**Séparation des natures de constat.** Un contrôle de configuration établit un fait vérifiable et
immédiatement actionnable : il porte une criticité et peut plafonner le score. Un contrôle
d'historique produit une piste d'investigation. Les confondre a un coût pratique : une machine
correctement durcie sortait « Insuffisant » à cause d'un agent bavard, et le seul chiffre que retient
un lecteur devenait faux.

**Score et plafonnement.** Le score pondère les seuls contrôles de configuration effectivement
tranchés. Un écart de criticité critique plafonne le score à 49, quel que soit le nombre de contrôles
conformes par ailleurs.

**Couverture d'audit.** Distincte du score. Elle indique la proportion de contrôles réellement
évalués. **Un « aucun écart » obtenu sur une couverture faible n'est pas un état sain** : sous le
seuil, l'audit est déclaré non concluant et le code de sortie est forcé à 4.

**Codes de sortie** (mode fichier) : `0` aucun écart · `1` écarts faibles/moyens · `2` écart élevé ·
`3` écart critique · `4` audit non concluant · `5` erreur d'exécution. Un écart avéré prime sur le
caractère non concluant. En consolidation de parc, lire **toujours** la colonne `Couverture` avec le
code de sortie.

**MITRE ATT&CK.** Chaque contrôle porte les identifiants de technique qu'il contraint ou dont il
détecte la trace (colonne `Technique` de l'export, sous-titre dans le rapport). Le rattachement
qualifie le contrôle, pas la machine : il ne signifie pas que la technique a été observée.

## Familles de contrôles

| Famille | Périmètre |
|---|---|
| Socle firmware | Secure Boot, options de démarrage du noyau |
| Intégrité noyau | VBS, HVCI, Credential Guard, protection LSA, protection DMA |
| Anti-BYOVD | WDAC / App Control, liste de blocage Microsoft, règle ASR pilotes, inventaire des pilotes et minifiltres tiers, correspondance d'empreintes |
| Intégrité de l'agent | détection multi-éditeurs, état des services, anti-sabotage, mode sans échec, fraîcheur des signatures |
| Télémétrie | rattachement et remontée console, journalisation PowerShell, AMSI, exclusions, rétention des journaux |
| Réduction de surface | posture des règles ASR |
| Historique (30 j) | arrêts de services de sécurité, désactivations de protection, installation de pilotes noyau, refus de chargement, effacement de journaux, collecteur indépendant — restitué en `À TRIER`, hors score |
| Privilèges | composition des administrateurs locaux, LAPS, UAC |

## Référentiel d'empreintes

`AGILLY_LOLDrivers_Empreintes.csv` — schéma `algo;empreinte;pilote;hvci;sources`, UTF-8 avec BOM,
séparateur point-virgule.

**Sources de la liste publiée** : LOLDrivers (loldrivers.io) et la transformation lisible par machine
de la Microsoft Vulnerable Driver Blocklist. **MalwareBazaar est désactivé par défaut** et n'entre pas
dans la liste publiée ; son activation nécessite une clé API personnelle et produit une liste qui ne
doit pas porter le même numéro de version.

**Comptage** : une ligne par *empreinte de fichier*. Un même pilote peut contribuer jusqu'à trois
entrées (MD5, SHA1, SHA256) : le total d'empreintes est donc supérieur au nombre d'échantillons
recensés en amont. Le script d'audit calcule les trois algorithmes, une comparaison SHA256 seule
ignorerait la majeure partie du référentiel.

**Régénération** : le référentiel est reconstruit par AGILLY avec un outil de collecte interne, non
distribué ici. Cet outil s'exécute sur un poste d'administration disposant d'un accès réseau, jamais
sur un poste client et jamais pendant un audit ; il ne télécharge que des métadonnées, jamais un
binaire de pilote, et n'exécute rien de ce qu'il télécharge. Chaque publication comprend le CSV et
son `.sha256`. Les sources amont étant publiques, un tiers peut reconstituer une liste équivalente :
la colonne `sources` indique d'où vient chaque entrée.

**Politique de versionnement des sources.** Les sources amont ne sont pas épinglées sur un commit :
elles évoluent en continu. Toute régénération destinée à publication doit être comparée à la version
précédente (variation du nombre d'entrées, disparition d'une source) avant diffusion. Actualisation
prévue : trimestrielle.

**Portée du contrôle par empreinte.** C'est un contrôle de *détection* : il repère un échantillon
précis, y compris un pilote **déjà installé** — angle mort de la règle ASR et de la liste Microsoft.
Une autre version compilée du même pilote passe au travers. Le contrôle *préventif* reste WDAC par
signataire.

La comparaison porte sur tous les pilotes noyau en exécution qui ne sont pas édités par Microsoft,
**y compris ceux signés WHQL ou par attestation** : le sujet de ces certificats porte
`O=Microsoft Corporation` alors qu'il s'agit de pilotes tiers contresignés, et c'est précisément la
classe de pilotes qu'exploite le BYOVD. Les minifiltres qui ne sont pas enregistrés comme services
sont comparés séparément, pour qu'aucun module chargé n'échappe au contrôle.

## Documentation

- Note technique d'ingénierie : *Vecteurs d'Évasion EDR & Architecture de Durcissement* (v1.0) —
  [`docs/Note_Technique_Evasion_EDR_AGILLY_v1.pdf`](docs/Note_Technique_Evasion_EDR_AGILLY_v1.pdf)
  ([version HTML](docs/Note_Technique_Evasion_EDR_AGILLY_v1.html))
- Article de contexte — `<URL À COMPLÉTER APRÈS PUBLICATION>`

> Le lien de l'article reste ouvert tant que la publication n'a pas eu lieu. Il est le dernier
> élément à renseigner : le renseigner d'avance reviendrait à publier un lien mort.

## Licence

Code et données sous [Apache 2.0](LICENSE), par compatibilité avec le référentiel LOLDrivers dont le
CSV est dérivé. Attributions des sources amont : voir [NOTICE](NOTICE).

## Contact

AGILLY Cyberdéfense — infos@agilly.net — www.agilly.net

Retour terrain bienvenu par *issue*, en particulier : un agent de sécurité non reconnu par la
détection multi-éditeurs, ou une correspondance d'empreinte contestée (la colonne `sources` du CSV
permet de retracer l'origine de l'entrée).
