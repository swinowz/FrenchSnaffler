# ShareAuditor

**Repérer les identifiants et fichiers sensibles accessibles dans les partages Windows, puis produire un rapport exploitable.**

ShareAuditor est la version développée par **swinowz** à partir de [Snaffler](https://github.com/SnaffCon/Snaffler). Le projet conserve son moteur de découverte Active Directory/SMB et ses règles TOML, mais évolue vers un outil d’audit centré sur l’extraction d’identifiants, les documents bureautiques, les règles francophones et le reporting Excel.

Le dépôt garde son nom historique `Snaffler` ; l’exécutable produit est **`ShareAuditor.exe`**. Ce README décrit les sources de cette branche, y compris les évolutions qui peuvent ne pas encore figurer dans une version publiée.

## Ce que fait l’outil

- Découvrir des machines via Active Directory et leurs partages accessibles, ou analyser directement un dossier local ou un chemin UNC.
- Classer les fichiers selon leur nom, leur extension, leur chemin et leur contenu, avec des règles TOML modifiables.
- Rechercher des mots de passe, chaînes de connexion, jetons, clés privées et configurations sensibles ; exploiter aussi les termes français comme « mot de passe », « identifiant » et « utilisateur ».
- Lire les documents Excel et Word couverts par les règles, puis tenter d’en extraire les couples utilisateur/mot de passe.
- Produire un rapport Excel, un journal texte, du JSON ou du TSV, et copier les fichiers trouvés si l’option de collecte est activée.

L’analyse utilise les droits du compte Windows courant. Une détection reste un indice à vérifier : elle ne prouve ni la validité d’un identifiant ni son niveau de privilège.

## Ce qui distingue ShareAuditor de Snaffler

Les ajouts de ce fork portent sur les points suivants ; ils s’ajoutent aux fonctions de découverte et de classification héritées.

| Évolution | Apport dans ShareAuditor |
|---|---|
| **Rapport Excel avec `-t auto`** | Feuille `Findings`, extraction d’identifiants, aperçu du contenu, couleurs et tableau filtrable. |
| **Signatures cloud actives** | GitHub, Google, Azure, JWT et Kubernetes via les relais par défaut ; authentification Docker dans ses fichiers de configuration. |
| **Règles francophones** | Recherche dans les noms de fichiers, le texte et les en-têtes de tableaux de mots de passe. |
| **Analyse de contenu groupée** | Lecture du contenu mutualisée entre plusieurs règles d’un même relais, pour réduire les lectures répétées. |
| **Lecture bureautique retravaillée** | ExcelDataReader pour lire les classeurs ligne par ligne ; extraction directe du XML des DOCX, avec prise en compte des tableaux, en-têtes, pieds de page, notes de bas de page, notes de fin et commentaires. |
| **Formats OpenDocument** | Fichiers LibreOffice `.odt`, `.ods`, `.odp`, `.ott`, `.ots` analysés sans bibliothèque supplémentaire ; les documents chiffrés sont signalés en `PasswordProtectedFile`. |
| **Gestion des ressources** | Files de messages bornées, contenu complet conservé seulement pour l’export Excel, fermeture de handles et suppression de collectes mémoire forcées bloquantes. |
| **Concurrence et suivi du scan** | Choix automatique du nombre de workers, option `-x` pour le fixer, compteurs de tâches et suivi du débit, de la progression et de la mémoire. |
| **Qualité des résultats** | Déduplication par fichier et preuve détectée, filtrage de la clé AWS d’exemple publique, sorties JSON/texte corrigées. |
| **Certificats** | Chargement via `X509CertificateLoader` et clés éphémères (aucune écriture dans le magasin de clés). Les PEM avec clé privée RSA, PKCS#8 ou chiffrée sont reconnus, ainsi que les clés PEM seules (`PrivateKeyWithoutCertificate`). |
| **Archives** | Action `EnterArchive` (zip, 7z, rar, tar, gz, bz2, xz). Chaque membre garde son nom et ses dossiers, donc les règles par nom (`id_rsa`, `unattend.xml`, `web.config`) et par chemin (`\.ssh\`, `\.aws\`) s’appliquent aussi dans les archives. Le rapport indique `archive.zip!dossier\fichier`, y compris pour les archives imbriquées. Profondeur et tailles sont contrôlées pendant l’extraction ; les chemins `..` sont neutralisés. |
| **Bibliothèque SCCM** | Dans `SCCMContentLib$`, les fichiers sont stockés sous leur hash (`FileLib`) ; ShareAuditor lit les `.INI` de `DataLib` et analyse chaque fichier sous son vrai nom (`unattend.xml`, scripts, clés). Le rapport indique le chemin `DataLib\<paquet>\...`, et `-m` collecte le fichier sous ce nom. |
| **Reprise des longs scans** | `--checkpoint <fichier>` mémorise les dossiers et machines terminés ; relancer la même commande reprend là où le scan s’est arrêté, sans écraser le premier rapport. |
| **Autre compte réseau** | `--username DOMAINE\compte` : les accès SMB et LDAP utilisent ce compte. Si la machine peut vérifier le compte (jointe au domaine, ou compte local), le mot de passe est contrôlé au démarrage ; sinon le compte sert aux seuls accès réseau, comme `runas /netonly`, et un avertissement l’indique. Sans `--password`, le mot de passe est demandé sans écho. |
| **Règles supplémentaires** | Disques de VM (`.vmdk`, `.vhdx`…), `set "MOT_DE_PASSE=…"` / `set mdp=…` dans les scripts batch (variables `%x%`/`!x!` ignorées), clés PuTTY : Black sans phrase de passe, Red si chiffrée. |
| **Socle actuel** | Cible Windows x64 sous .NET 10, Server GC, GC concurrent et Tiered PGO. |

Ces changements visent à réduire le coût des scans et à faciliter le traitement des résultats. Aucun gain chiffré universel n’est annoncé : le débit dépend du réseau, des documents, des règles et des ressources disponibles. L’export Excel conserve le classeur en mémoire ; ce n’est pas une sortie à mémoire constante.

## Comparatif avec Snaffler

Mesure du 25 novembre 2026, sur la même VM Windows 11 (2 vCPU, 8 Go) et le même corpus synthétique de 50 292 fichiers (1,8 Go, 462 dossiers). Les deux outils tournent avec leurs réglages par défaut et `-r 1000000`, en 3 passes alternées (médianes).

| | Snaffler 1.0.244 (release officielle) | ShareAuditor |
|---|---|---|
| Temps de travail réel (fin de l’activité CPU) | 13,0 s | **10,8 s** |
| CPU consommé | 21,3 s | **15,7 s** |
| Durée jusqu’à la fin du programme | ~301 s | **10,8 s** |
| Détections | 2 974 | 1 740 |

- À travail égal, ShareAuditor est environ 1,2 fois plus rapide et consomme un quart de CPU en moins.
- Snaffler attend son contrôle de fin périodique (5 minutes par défaut, option `-e`) avant de s’arrêter ; ShareAuditor vérifie la fin du scan toutes les 2 secondes.
- Les détections supplémentaires de Snaffler sont la clé d’exemple publique d’AWS (`AKIAIOSFODNN7EXAMPLE`, 1 854 fois) et des doublons d’une même règle sur un même fichier (459). Les seuls fichiers signalés par Snaffler et absents du rapport de ShareAuditor ne contiennent que cette clé d’exemple ; ShareAuditor signale en plus 10 classeurs Excel contenant des identifiants, que Snaffler ne lit pas.
- Snaffler consomme moins de mémoire sur ce corpus (environ 160 Mo contre 520 à 600 Mo), en raison du parallélisme et du GC serveur.

Ces chiffres dépendent du corpus : sur des partages réseau, la latence SMB pèse davantage que le CPU.

## Démarrage rapide

Depuis PowerShell, dans le dossier de publication :

```powershell
# Aide
.\ShareAuditor.exe -h

# Dossier local : rapport Excel + journal texte
.\ShareAuditor.exe -i "C:\Audit\Donnees" -t auto -o "C:\Audit\rapport.log" -s

# Partage précis, avec limite de contenu portée à 5 Mo
.\ShareAuditor.exe -i "\\SRV-FICHIERS\Commun" -t auto -o "C:\Audit\partage.log" -r 5000000 -s

# Machines ciblées : résultat JSON
.\ShareAuditor.exe -n "SRV-FICHIERS,SRV-ARCHIVES" -t json -o "C:\Audit\resultats.json" -s

# Découverte des partages d’un domaine, sans parcourir leurs fichiers
.\ShareAuditor.exe -d "exemple.test" -a -s
```

Les dossiers de sortie doivent exister. Avec `-t auto -o "C:\Audit\rapport.log"`, le classeur est écrit dans **`C:\Audit\rapport.xlsx`**. Utiliser un nom de journal distinct du classeur, comme dans les exemples. Sans `-o`, le nom Excel par défaut reste `Snaffler-Report-<date>-<heure>.xlsx`, dans le dossier courant.

## Options principales

### Périmètre

| Option | Rôle |
|---|---|
| `-i <chemin>` | Analyser un dossier local ou UNC ; désactive la découverte de machines et de partages. Plusieurs chemins peuvent être séparés par des virgules. |
| `-n <cibles>` | Une machine, une liste séparée par des virgules, ou le chemin complet d’un fichier contenant une machine par ligne. |
| `-d <domaine>` | Domaine Active Directory à interroger. |
| `-c <contrôleur>` | Contrôleur de domaine à interroger. |
| `-k <fichier>` | Liste de machines à exclure. |
| `-a` | Découvrir les partages sans parcourir leurs fichiers. |
| `-f` | Limiter la découverte de partages à DFS. |
| `--username <compte>` | Accéder au réseau avec un autre compte (`DOMAINE\compte` ou `compte@domaine`), comme `runas /netonly`. |
| `--password <mdp>` | Mot de passe de `--username` ; s’il est omis, il est demandé sans écho, ce qui évite l’historique et la liste des processus. |

### Sortie et collecte

| Option | Rôle |
|---|---|
| `-s` | Afficher les résultats dans la console. |
| `-o <fichier>` | Écrire un journal ; fournit aussi le nom de base du rapport Excel. |
| `-t auto` | Générer le rapport `.xlsx`. |
| `-t json` | Écrire un journal JSON ; utiliser `-o` pour obtenir le fichier final normalisé. |
| `-t plain` | Journal texte, format par défaut. |
| `-y` | Sortie texte séparée par des tabulations, par exemple avec `-o resultats.tsv`. |
| `-v <niveau>` | `Trace`, `Debug`, `Info` ou `Data` (résultats uniquement). |
| `-m <dossier>` | Copier les fichiers retenus dans un dossier de collecte. |
| `-l <octets>` | Taille maximale d’un fichier à collecter : **10 000 000 octets** par défaut. |

### Analyse et réglages

| Option | Rôle |
|---|---|
| `-r <octets>` | Taille maximale d’un fichier dont le contenu sera analysé : **1 000 000 octets** par défaut dans les sources actuelles. |
| `-j <nombre>` | Taille du contexte autour d’une correspondance : **200** par défaut. |
| `-x <nombre>` | Fixer le nombre total de workers ; sans cette option, calcul automatique à partir des ressources et des cibles disponibles au moment du calcul. |
| `-b <0–3>` | Filtrer les niveaux de triage. `0` conserve tout ; `1` exclut Green ; `2` exclut aussi Yellow ; `3` exclut aussi Red et conserve Black. |
| `-u` | Enrichir certaines recherches avec les comptes intéressants du domaine. |
| `-p <dossier>` | Charger un jeu de règles TOML à la place des règles par défaut. |
| `-z <fichier>` | Charger une configuration TOML. Elle remplace l’objet de configuration construit à partir des options CLI ; éviter de mélanger les deux pour surcharger des valeurs. |
| `-z generate` | Générer `default.toml` à partir de la configuration courante. |
| `-e <minutes>` | Régler l’intervalle de statut et le délai de collecte LDAP ; ce n’est pas une limite globale de durée du scan. |
| `--checkpoint <fichier>` | Reprise d’un scan interrompu : relancer exactement la même commande. Les dossiers à moitié traités sont rescannés ; les résultats de la reprise vont dans `<sortie>-resume-N`. |
| `-w <fichier>` | Diagnostic de l’extraction d’identifiants sur un fichier. Pour les classeurs, ce diagnostic lit les données brutes et ne remplace pas un scan bureautique complet. |

Les valeurs ci-dessus correspondent au code actuel et à l’aide intégrée (`-h`).

## Lire le rapport Excel

La feuille `Findings` contient les colonnes suivantes :

| Colonne | Contenu |
|---|---|
| `Severity` | Classement de la règle : Green, Yellow, Red ou Black. |
| `Type` | Type de résultat. |
| `Hostname` | Hôte ou information déduite du chemin. |
| `FilePath` | Chemin du fichier détecté. |
| `RuleName` | Règle à l’origine du résultat. |
| `Username`, `Password` | Identifiants extraits lorsqu’ils ont pu être reconnus. |
| `DateFound` | Date de détection. |
| `Preview` | Aperçu du contenu retenu. |

Une ligne peut signaler un fichier intéressant sans contenir de couple utilisateur/mot de passe. Les documents identifiés comme protégés par mot de passe sont signalés pour examen manuel ; l’outil ne déchiffre pas leur contenu. Les journaux et classeurs peuvent contenir des secrets en clair : les conserver hors du dépôt.

## Règles et configuration

Les règles livrées avec l’exécutable sont embarquées à la compilation depuis [`Snaffler/SnaffRules/DefaultRules`](Snaffler/SnaffRules/DefaultRules). Pour les modifier sans recompiler :

```powershell
.\ShareAuditor.exe -i "C:\Audit\Donnees" -p "C:\Audit\Regles" -t auto -o "C:\Audit\personnalise.log" -s
```

Le dossier fourni avec `-p` doit contenir un **jeu complet**, incluant les règles de relais et leurs cibles. Un dossier `SnaffRules\DefaultRules` placé à côté de l’exécutable peut également être chargé automatiquement ; à défaut de règles externes, l’outil utilise les ressources embarquées. Des règles définies directement dans la configuration TOML prennent priorité sur ce chargement.

Une règle de contenu doit être reliée à une règle de fichiers via `RelayTargets` pour être exécutée. Les signatures de `KeepModernCloudSecrets.toml` sont **actives dans les règles par défaut** : GitHub, Google, Azure, JWT et Kubernetes sont reliés aux configurations, aux langages et aux documents Office déjà analysés. Des relais complémentaires couvrent les fichiers `.env` et `.env.*`, les noms `config` et `credentials`, ainsi que les scripts shell et les fichiers Terraform/HCL. La recherche Docker est limitée aux fichiers `.docker/config.json` et `.dockercfg`, avec prise en charge des champs JSON entre guillemets.

Pour partir d’une configuration correspondant à la version exécutée :

```powershell
.\ShareAuditor.exe -z generate
.\ShareAuditor.exe -z "C:\Audit\audit.local.toml"
```

La configuration expose aussi `MaxArchiveDepth` (3), `MaxArchiveEntries` (10 000), `MaxArchiveEntryBytes` (50 Mio) et `MaxArchiveTotalBytes` (500 Mio). La profondeur compte les archives imbriquées depuis l’archive trouvée sur le partage, et le budget `MaxArchiveTotalBytes` est partagé par toute cette arborescence. La taille de chaque membre est vérifiée pendant la copie : une taille déclarée mensongère ne permet pas de dépasser la limite.

## Compiler et publier

Prérequis : **SDK .NET 10**, accès aux paquets NuGet et Windows x64 pour exécuter l’outil. Depuis la racine du dépôt :

```powershell
git clone https://github.com/swinowz/Snaffler.git
cd Snaffler

# Publication autonome Windows x64 : pas de runtime à installer sur la cible
dotnet publish .\Snaffler\Snaffler.csproj -c Release -r win-x64 --self-contained true -o .\publish-release
```

Le dossier `publish-release` contient `ShareAuditor.exe` et ses dépendances : **copier le dossier complet**. Les règles par défaut sont embarquées. Le projet reste organisé en `Snaffler` (CLI et règles) et `SnaffCore` (découverte, analyse et sorties) ; ces noms internes sont historiques.

La commande compile la branche actuellement extraite. Les fonctions décrites pour une branche de développement nécessitent que ces sources aient été intégrées à la branche récupérée ; une ancienne publication peut encore cibler .NET 8.

## Vérifier les signatures et les parseurs

```powershell
dotnet run --project .\tests\CloudRulesRegression
```

Ce test de régression charge les règles TOML par défaut et utilise le moteur réel de classification sur des fichiers temporaires synthétiques. Il vérifie les six familles de signatures, les relais de fichiers, un document DOCX et des cas négatifs. D’autres séries couvrent la lecture XLS/XLSX, les parseurs Word et Outlook, l’export Excel, les archives (règles par nom dans une archive, chemin affiché, archives imbriquées, profondeur, chemins `..`, limite de taille), les formats OpenDocument et notes Word, et les certificats (PEM avec ou sans clé, DER, PFX sans mot de passe, mot de passe faible ou fort). Aucun véritable secret n’est stocké dans les tests. Il peut être exécuté sous Linux pour cette partie locale du moteur : l’initialisation de l’identité Windows est contournée dans le test uniquement. La découverte AD/SMB n’est pas couverte par ce test.

## Limites actuelles

- Les règles filtrent les fichiers avant l’analyse de contenu. Augmenter `-r` ne suffit pas à faire analyser tous les formats.
- Le parsing prend en charge les formats Office et OpenDocument sélectionnés par les relais. Les PDF, présentations PowerPoint, PST/OST, bases SQLite, OneNote et images (OCR) ne sont pas analysés par les règles par défaut.
- L’analyse d’archives extrait chaque membre dans le dossier temporaire de l’utilisateur, puis le supprime. La date et la taille affichées sont celles du membre. L’option `-m` (copie des fichiers retenus) copie le membre extrait, rangé sous le chemin de l’archive.
- Des tâches réseau considérées comme bloquées peuvent être abandonnées. Les accès refusés, erreurs d’E/S et timeouts peuvent donc laisser un scan incomplet ; consulter les journaux.
- Le nombre de workers automatique est un point de départ. Sur un serveur SMB lent ou avec de gros documents, fixer une valeur prudente avec `-x`, par exemple `-x 4`.

## Contribution et données locales

Versionner les sources, les règles et les exemples synthétiques. Conserver les rapports, fichiers collectés, listes de cibles et configurations personnelles hors du dépôt, par exemple dans les dossiers ignorés `reports/`, `collected/` ou `local-config/`. Le fichier `default.toml` généré peut contenir des informations locales et est ignoré.

Le répertoire [`snafflertest`](snafflertest/README.md) est un corpus historique de noms de fichiers. Les anciennes clés privées ont été remplacées par des marqueurs inertes ; il ne faut pas y déposer de données réelles.

## Origine et licence

Développé par **swinowz**, à partir du travail des auteurs et contributeurs de [Snaffler / SnaffCon](https://github.com/SnaffCon/Snaffler). Le moteur de découverte et une partie des règles proviennent de ce projet ; les ajouts spécifiques à ShareAuditor sont présentés ci-dessus.

Le fichier [`LICENSE`](LICENSE) du dépôt contient la **GNU GPL version 3**. Les dépendances conservent leurs propres conditions ; le code de l’export configure notamment EPPlus en mode `NonCommercial`. Ce paramètre ne remplace pas les conditions de licence d’EPPlus.
