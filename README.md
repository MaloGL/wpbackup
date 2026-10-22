# wpbackup

Script Python de **sauvegarde et restauration de sites WordPress**, pensé pour le **RGPD** : chiffrement des archives, rétention obligatoire, journal d'audit, secrets protégés.

Un seul fichier (`wpbackup.py`), des dépendances minimales, compatible **Debian, Ubuntu, RHEL** et fonctionnant en **conteneur LXC** (aucun montage système requis pour SMB et S3).

## Fonctionnalités

- **Profils multiples** : un fichier JSON par scénario de sauvegarde
- **Bases de données** : une ou plusieurs bases MySQL / MariaDB par profil (dump cohérent `--single-transaction`)
- **Répertoires** : un ou plusieurs dossiers ou fichiers, avec motifs d'exclusion
- **Chiffrement optionnel** : AES-256-GCM, clé dérivée du mot de passe par scrypt, détection de toute altération ou troncature
- **Destinations** : dossier local, NFS, S3 (AWS ou compatible : OVH, Scaleway, MinIO…), SMB/CIFS
- **Rétention** : durée choisie par profil, appliquée **uniquement après une sauvegarde réussie et vérifiée**
- **Notification SMTP** : succès ou échec, avec la liste des sauvegardes expirées supprimées
- **Restauration (rollback)** à une date choisie, avec dump de sécurité avant import
- **Planification par profil** (`6h`, `1d`, `7d`…) via un seul cron ou timer systemd
- **Assistant interactif** de création de profil, qui lit `wp-config.php` pour détecter la base
- **Exécution manuelle** d'un profil ou de tous

## Prérequis

### Paquets système

| Besoin | Debian / Ubuntu | RHEL / Rocky / Alma |
|---|---|---|
| Python ≥ 3.8 | `python3 python3-venv python3-pip` | `python3.11 python3.11-pip` (RHEL 8) ou `python3` (RHEL 9) |
| `mysqldump` et `mysql` | `mariadb-client` (ou `mysql-client`) | `mariadb` |
| Planification | `cron` ou systemd | `cronie` ou systemd |
| NFS (montage automatique) | `nfs-common` | `nfs-utils` |
| Diagnostic SMB (facultatif) | `smbclient` | `samba-client` |

### Modules Python

| Module | Utilité | Requis si |
|---|---|---|
| `cryptography` | chiffrement | chiffrement activé |
| `boto3` | stockage S3 | stockage S3 |
| `smbprotocol` | stockage SMB | stockage SMB |

Le reste utilise la bibliothèque standard.

## Installation

### Debian / Ubuntu

```bash
apt update
apt install -y python3 python3-venv python3-pip mariadb-client cron nfs-common smbclient

mkdir -p /opt/wpbackup
python3 -m venv /opt/wpbackup/venv
/opt/wpbackup/venv/bin/pip install --upgrade pip
/opt/wpbackup/venv/bin/pip install -r requirements.txt

cp wpbackup.py /opt/wpbackup/
chmod 700 /opt/wpbackup/wpbackup.py
```

### RHEL / Rocky / Alma

```bash
dnf install -y python3.11 python3.11-pip mariadb cronie nfs-utils samba-client
systemctl enable --now crond

mkdir -p /opt/wpbackup
python3.11 -m venv /opt/wpbackup/venv
/opt/wpbackup/venv/bin/pip install --upgrade pip
/opt/wpbackup/venv/bin/pip install -r requirements.txt

cp wpbackup.py /opt/wpbackup/
chmod 700 /opt/wpbackup/wpbackup.py
```

> Un venv est recommandé : Debian 12 et Ubuntu 24 refusent `pip install` en global (PEP 668).

### Raccourci `wpbackup`

```bash
cat > /usr/local/bin/wpbackup <<'EOF'
#!/bin/sh
exec /opt/wpbackup/venv/bin/python /opt/wpbackup/wpbackup.py "$@"
EOF
chmod 700 /usr/local/bin/wpbackup
```

### Vérification

```bash
wpbackup doctor
```

Les lignes `[!!]` concernant des fonctions que vous n'utilisez pas (par exemple `mount.nfs` si vous êtes en SMB) peuvent être ignorées.

## Démarrage rapide

```bash
# 1. Créer un profil (assistant interactif)
wpbackup create-profile monsite

# 2. Lancer une première sauvegarde
wpbackup run monsite

# 3. Vérifier
wpbackup list-backups monsite

# 4. Activer la planification automatique
/opt/wpbackup/venv/bin/python /opt/wpbackup/wpbackup.py install-scheduler
```

L'assistant demande le dossier du site, détecte la base dans `wp-config.php`, puis pose les questions sur le chiffrement, la rétention, la fréquence, le stockage et les notifications. Il propose aussi un test d'envoi de mail et un test d'accès au stockage.

## Commandes

| Commande | Description |
|---|---|
| `create-profile [NOM]` | Assistant de création d'un scénario |
| `list-profiles` | Liste les profils, leur fréquence et leur dernier succès |
| `show-profile NOM` | Affiche un profil (secrets masqués) |
| `run NOM [NOM…]` | Exécute un ou plusieurs profils |
| `run --all` | Exécute tous les profils actifs |
| `run-due` | Exécute les profils dont l'échéance est atteinte (appelé par cron/systemd) |
| `list-backups NOM` | Liste les sauvegardes et leur date d'expiration |
| `restore NOM [options]` | Restaure une sauvegarde |
| `test-mail NOM` | Envoie un mail de test |
| `doctor` | Vérifie les dépendances |
| `install-scheduler [--type auto\|cron\|systemd] [--tick MIN]` | Installe la planification |

Option globale : `-v` pour des logs détaillés.

Codes de sortie : `0` succès, `1` échec d'une sauvegarde ou restauration, `2` erreur de configuration.

## Restauration (rollback)

```bash
wpbackup restore monsite                          # menu interactif
wpbackup restore monsite --date 2026-10-20        # dernière sauvegarde ≤ cette date
wpbackup restore monsite --date "2026-10-20 14:30"
wpbackup restore monsite --backup monsite_20261020-030000.tar.gz.enc
```

| Option | Effet |
|---|---|
| `--date` | Choisit la dernière sauvegarde antérieure ou égale à la date (`2026-10-20`, `2026-10-20 14:30`, `20/10/2026`) |
| `--backup` | Nom exact de l'archive |
| `--only db\|files\|all` | Restaure seulement la base, les fichiers, ou les deux |
| `--db NOM` | Limite à cette base (répétable) |
| `--path LABEL` | Limite à ce répertoire (répétable) |
| `--target DIR` | Extrait dans `DIR` sans rien écraser (inspection) |
| `--no-safety` | Pas de dump de sécurité avant l'import SQL |
| `--yes` | Pas de confirmation |

Déroulement : téléchargement, vérification du SHA-256, déchiffrement, confirmation, puis :

- **Bases** : dump de sécurité de l'état actuel dans `/var/lib/wpbackup/pre-restore/`, puis import.
- **Répertoires** : extraction dans un dossier temporaire voisin, puis l'ancien dossier est renommé en `<nom>.pre-restore-<date>` avant d'être remplacé.

> **RGPD** : les dumps de sécurité et les dossiers `.pre-restore-*` contiennent des données personnelles. Supprimez-les une fois la restauration validée. Si des demandes d'effacement ont été traitées depuis la date restaurée, réappliquez-les.

La restauration doit s'exécuter en **root** pour restituer fidèlement propriétaires et droits.

## Configuration d'un profil

Les profils sont des fichiers JSON dans `/etc/wpbackup/profiles/NOM.json` (droits `600`). Exemple complet :

```json
{
  "description": "Site vitrine",
  "enabled": true,
  "databases": [
    { "name": "wp_prod", "user": "wpuser", "password": "file:/etc/wpbackup/secrets/db.key",
      "host": "192.168.10.20", "port": 3306 }
  ],
  "paths": [
    { "path": "/var/www/monsite/public", "label": "public" }
  ],
  "exclude": ["wp-content/cache", "wp-content/upgrade", "*.log"],
  "encryption": { "enabled": true, "password": "file:/etc/wpbackup/secrets/monsite.key" },
  "retention": { "days": 30, "keep_min": 1 },
  "schedule": { "interval": "1d" },
  "storage": {
    "type": "smb", "server": "192.168.10.12", "share": "sauvegardes", "path": "monsite",
    "username": "backup", "password": "file:/etc/wpbackup/secrets/smb.key"
  },
  "smtp": {
    "host": "smtp.example.com", "port": 587, "security": "starttls",
    "user": "alerte@example.com", "password": "env:SMTP_PASSWORD",
    "from": "alerte@example.com", "to": ["admin@example.com"], "notify_on": "always"
  }
}
```

### Champs

| Section | Champ | Description |
|---|---|---|
| racine | `enabled` | `false` exclut le profil de `run --all` et `run-due` |
| racine | `work_dir` | Dossier temporaire (défaut `/var/tmp/wpbackup`) |
| `databases[]` | `name`, `user`, `password` | Obligatoires (`name` : lettres, chiffres, `_`, `$`, `-`) |
| | `host`, `port`, `socket` | Défaut `localhost` et `3306` ; `socket` remplace host/port |
| | `extra_args` | Options supplémentaires pour `mysqldump` (liste) |
| `paths[]` | `path` | Chemin absolu d'un dossier ou d'un fichier |
| | `label` | Nom dans l'archive (défaut : nom du dossier) |
| `exclude` | motifs | Relatifs à chaque répertoire : `wp-content/cache`, `*.log`… |
| `encryption` | `enabled`, `password` | Mot de passe 12 caractères minimum recommandé |
| `retention` | `days` | **Obligatoire**, entier ≥ 1 |
| | `keep_min` | Nombre minimal de sauvegardes toujours conservées (défaut 1) |
| `schedule` | `interval` | `30m`, `6h`, `1d`, `1w` (minimum `5m`) ou `manuel` |
| `smtp` | `security` | `starttls` (587), `ssl` (465) ou `none` |
| | `notify_on` | `always`, `failure` ou `never` |

### Secrets

Toute valeur secrète accepte trois formes :

- valeur en clair : `"password": "monmotdepasse"`
- variable d'environnement : `"password": "env:NOM_VARIABLE"`
- fichier : `"password": "file:/etc/wpbackup/secrets/fichier.key"` (recommandé, droits `600`)

### Destinations

**Local**
```json
"storage": { "type": "local", "path": "/var/backups/wpbackup" }
```

**NFS** : utilise un point de montage existant, ou le monte si `server` et `export` sont fournis.
```json
"storage": { "type": "nfs", "mount_point": "/mnt/backup-nfs",
             "server": "192.168.10.12", "export": "/export/backups", "options": "vers=4,soft,timeo=100" }
```

**S3** : AWS ou compatible. Sans clés, utilise les variables `AWS_*` ou un rôle IAM.
```json
"storage": { "type": "s3", "bucket": "mes-sauvegardes", "prefix": "wpbackup",
             "region": "eu-west-3", "endpoint_url": "https://s3.fr-par.scw.cloud",
             "access_key": "env:S3_KEY", "secret_key": "env:S3_SECRET",
             "sse": false, "storage_class": "STANDARD_IA" }
```

**SMB**
```json
"storage": { "type": "smb", "server": "nas.local", "share": "sauvegardes", "path": "monsite",
             "username": "backup", "domain": "MONDOMAINE", "password": "file:/etc/wpbackup/secrets/smb.key",
             "port": 445, "encrypt": false }
```

Chaque profil écrit dans son propre sous-dossier (`<destination>/<profil>/`).

## Format des sauvegardes

```
<profil>_<AAAAMMJJ-HHMMSS>.tar.gz[.enc]          archive
<profil>_<AAAAMMJJ-HHMMSS>.tar.gz[.enc].meta.json  métadonnées (date, taille, SHA-256)
```

L'archive contient `manifest.json`, les dumps (`db/<base>.sql`) et les fichiers (`files/<label>/…`). Chaque exécution produit une **sauvegarde complète** (pas d'incrémental).

Le chiffrement découpe l'archive en blocs de 1 Mo, chacun chiffré en AES-256-GCM. Un drapeau « dernier bloc » est authentifié, ce qui détecte aussi les troncatures.

> **Conservez le mot de passe de chiffrement hors du serveur** (gestionnaire de mots de passe). Sans lui, aucune restauration n'est possible.

## Rétention

Après chaque sauvegarde :

1. la sauvegarde est envoyée et sa taille vérifiée sur la destination ;
2. seulement si tout a réussi, les archives plus anciennes que `retention.days` sont supprimées (en conservant toujours les `keep_min` plus récentes) ;
3. le mail liste les archives supprimées et leur date.

En cas d'échec, **aucune suppression** n'est effectuée.

## Planification

```bash
python3 wpbackup.py install-scheduler --type auto --tick 10
```

Installe un cron (`/etc/cron.d/wpbackup`) ou un timer systemd (`wpbackup.timer`) qui lance `run-due` toutes les 10 minutes. Chaque profil se déclenche selon son propre `schedule.interval`. Après un échec, un nouvel essai a lieu au plus tôt une heure plus tard.

Utilisez le Python du venv pour que `cryptography`, `boto3` et `smbprotocol` soient disponibles.

## Fichiers et dossiers

| Chemin | Contenu |
|---|---|
| `/etc/wpbackup/profiles/` | profils JSON (`600`) |
| `/etc/wpbackup/secrets/` | mots de passe (`600`) |
| `/var/lib/wpbackup/` | état de planification, verrous, dumps de sécurité |
| `/var/log/wpbackup/wpbackup.log` | journal d'exécution |
| `/var/log/wpbackup/audit.log` | journal d'audit (JSON) |
| `/var/tmp/wpbackup/` | espace de travail temporaire |

Prévoyez dans le dossier de travail environ **deux fois la taille du site**. Les chemins se changent avec les variables `WPBACKUP_CONFIG_DIR`, `WPBACKUP_STATE_DIR`, `WPBACKUP_LOG_DIR` et `WPBACKUP_WORK_DIR`.

## RGPD et sécurité

Ce que le script met en œuvre :

- **Chiffrement** AES-256-GCM (art. 32), avec avertissement journalisé si désactivé
- **Limitation de la conservation** (art. 5-1-e) : rétention obligatoire et automatique
- **Responsabilité** (art. 5-2) : journal d'audit des sauvegardes, suppressions et restaurations
- **Confidentialité** : fichiers de configuration en `600`, mot de passe de base transmis par fichier d'options temporaire (jamais en ligne de commande), secrets masqués dans les logs et les mails, dumps en clair supprimés dès l'archive créée
- **Localisation** : avertissement si la région S3 AWS est hors UE
- **Mails** : uniquement des métadonnées, jamais de données personnelles

Ce que le script ne fait pas : il ne remplace pas votre analyse juridique. Documentez les durées de conservation dans votre registre des traitements, et traitez les demandes d'effacement en tenant compte de la présence des données dans les sauvegardes jusqu'à expiration.

## Notes LXC

- SMB et S3 fonctionnent directement depuis le conteneur, sans montage.
- NFS en **LXC non privilégié** : le montage depuis le conteneur est impossible. Montez le partage sur l'hôte et exposez-le au conteneur (point de montage lié), puis utilisez `mount_point` sans `server` ni `export`.
- Un dossier de destination `local` situé sur le même serveur ne protège pas d'une perte de la machine (règle 3-2-1).

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `STATUS_LOGON_FAILURE` (SMB) | Identifiants refusés par le serveur. Testez : `smbclient //SERVEUR/PARTAGE -U utilisateur -c ls`, puis essayez `domain`. Sur Samba, le mot de passe SMB est distinct du mot de passe système (`smbpasswd -a`) |
| `535 Authentication failed` (SMTP) | Mauvais identifiant, ou mot de passe d'application requis (Gmail), ou mauvais couple `port`/`security` |
| `mysqldump introuvable` | Installer `mariadb-client` (RHEL : `mariadb`) |
| `Module 'cryptography' manquant` | Lancer le script avec le Python du venv |
| Erreur de dump sur `PROCESS` ou `COLUMN_STATISTICS` | Gérée automatiquement (options détectées selon la version du client) |
| `Déchiffrement impossible` | Mauvais mot de passe, ou archive altérée |
| Profil « déjà en cours d'exécution » | Une autre exécution tient le verrou : attendre sa fin |

Privilèges MariaDB minimaux pour l'utilisateur de sauvegarde : `SELECT`, `LOCK TABLES`, `SHOW VIEW`. Pour restaurer, ajouter `INSERT`, `CREATE`, `ALTER`, `DROP`, `INDEX`.

## Limites

- Sauvegardes complètes uniquement (pas d'incrémental ni de déduplication)
- Bases MySQL / MariaDB uniquement
- Le fichier de profil contient des identifiants : protégez `/etc/wpbackup` (utilisez `file:` ou `env:` pour les secrets)
- Testé avec Python 3.12 ; compatible 3.8+ par conception

## Licence

À définir (par exemple MIT).
