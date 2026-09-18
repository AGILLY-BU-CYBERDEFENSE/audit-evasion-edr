# ===========================================================================
#  AGILLY Cyberdéfense
#  Collecte et consolidation des empreintes de pilotes vulnérables
#  Version 1.0
#
#  Régénère AGILLY_LOLDrivers_Empreintes.csv à partir de plusieurs sources
#  publiques, en conservant la provenance de chaque empreinte.
#
#  OUTIL DE BUILD — à exécuter sur un poste d'administration disposant d'un
#  accès réseau, PAS sur un poste client et PAS pendant un audit.
#
#  SÉCURITÉ :
#    - Ne télécharge QUE des métadonnées (JSON/CSV d'empreintes). Ne télécharge
#      JAMAIS de binaire de pilote : aucun pilote vulnérable ou malveillant
#      n'est déposé sur le poste de build.
#    - N'exécute rien de ce qui est téléchargé. Lecture et transformation
#      de texte uniquement.
#    - Ne retient que des empreintes de FICHIER (MD5/SHA1/SHA256), celles que
#      Get-FileHash calcule côté audit. Les Authentihash sont ignorés : ils ne
#      correspondraient pas et gonfleraient la liste de bruit.
#
#  PÉRIMÈTRE DE LA LISTE PUBLIÉE : le CSV diffusé publiquement est produit
#  depuis LOLDrivers (loldrivers.io) et la transformation lisible par machine
#  de la Microsoft Vulnerable Driver Blocklist. MalwareBazaar est DÉSACTIVÉ
#  par défaut (clé API requise) : une liste produite en l'activant n'est plus
#  celle qui est publiée et ne doit pas porter le même numéro de version.
#  Les sources ne sont pas épinglées sur un commit : toute régénération doit
#  être rejouée et comparée à la précédente avant diffusion.
#
#  SORTIE : un CSV « ; » au schéma consommé par l'audit
#           (algo;empreinte;pilote;hvci;sources), une ligne par empreinte,
#           en UTF-8 avec BOM — encodage à préserver.
#           Le script imprime l'empreinte SHA256 du CSV produit et l'écrit
#           dans un fichier « <nom>.csv.sha256 » adjacent, à publier avec le
#           CSV. Reporter la même valeur dans $LolDriversSha256 de l'audit
#           et dans la note technique.
# ===========================================================================

# --- Paramétrage -----------------------------------------------------------
# Dossier de sortie. Le fichier n'écrase pas la liste en production : il est
# écrit ici pour relecture, puis copié manuellement après contrôle.
$DossierSortie = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AGILLY-Empreintes'
$NomFichier    = 'AGILLY_LOLDrivers_Empreintes.csv'

# Sources (URLs surchargables). Chaque source peut être désactivée.
$UrlLoldrivers = 'https://www.loldrivers.io/api/drivers.csv'
# Drapeau « se charge malgré HVCI » : fichier SÉPARÉ dans le repo LOLDrivers,
# croisé par empreinte (il n'est pas porté par drivers.csv).
$UrlHvci = 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/bin/hvci_drivers.csv'
# Transformation machine-readable de la blocklist Microsoft (colonne FileHash
# = SHA256 de fichier). On tente le CSV puis le JSON en repli. À épingler sur
# un commit revu si la chaîne d'approvisionnement doit être maîtrisée.
$UrlMsBlocklistCsv  = 'https://raw.githubusercontent.com/Cyb3r-Monk/Microsoft-Vulnerable-Driver-Block-Lists/main/msft_vuln_driver_block_list.csv'
$UrlMsBlocklistJson = 'https://raw.githubusercontent.com/Cyb3r-Monk/Microsoft-Vulnerable-Driver-Block-Lists/main/msft_vuln_driver_block_list.json'

$ActiverLoldrivers  = $true
$ActiverMsBlocklist = $true

# MalwareBazaar (abuse.ch) : OPTIONNEL, désactivé par défaut. Nécessite une
# Auth-Key gratuite, fournie via la variable d'environnement AGILLY_MB_KEY.
# Feed bruité (tout type de malware) : filtré au type de fichier « sys ».
$ActiverMalwareBazaar = $false
$UrlMalwareBazaar     = 'https://mb-api.abuse.ch/api/v1/'
$TagsMalwareBazaar    = @('sys', 'vulnerable-driver', 'BYOVD')
$CleMalwareBazaar     = $env:AGILLY_MB_KEY

# Plancher de cohérence : en deçà, la collecte est jugée incomplète et la
# sortie n'est pas écrite (protège contre un CSV tronqué par une source en
# panne, cohérent avec $LolDriversMinimum côté audit).
$MinimumEmpreintes = 2000

$TimeoutSec = 60

# --- Empreintes vides à rejeter (fichier de taille nulle) ------------------
$EmpreintesVides = @(
    'd41d8cd98f00b204e9800998ecf8427e',                                  # MD5
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',                          # SHA1
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'   # SHA256
)

# ===========================================================================
#  MISE EN PLACE
# ===========================================================================

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
$ErrorActionPreference = 'Stop'

# Index consolidé : empreinte (minuscule) -> objet { Algo, Pilote, Hvci, Sources }
$index = @{}
$statsSource = [ordered]@{}

function Test-Empreinte {
    # Valide une empreinte hexadécimale et renvoie son algorithme, ou $null.
    param([string] $h)
    if ([string]::IsNullOrWhiteSpace($h)) { return $null }
    $x = $h.Trim().ToLower()
    if ($x -notmatch '^[a-f0-9]+$') { return $null }
    if ($EmpreintesVides -contains $x) { return $null }
    switch ($x.Length) {
        32 { return 'MD5' }
        40 { return 'SHA1' }
        64 { return 'SHA256' }
        default { return $null }
    }
}

function Protect-Champ {
    # Neutralise ce qui casserait le CSV « ; » : point-virgule, guillemets,
    # retours à la ligne. Les noms de pilote sont normalement ASCII simples.
    param([string] $s)
    if ($null -eq $s) { return '' }
    return ($s -replace '[;\r\n"]', ' ').Trim()
}

function Add-Empreinte {
    # Ajoute ou fusionne une empreinte dans l'index. Dédup par valeur ;
    # fusion des sources ; conservation de la première annotation non vide et
    # du drapeau HVCI dès qu'une source le signale.
    param([string] $Hash, [string] $Pilote, [bool] $Hvci, [string] $Source)
    $algo = Test-Empreinte $Hash
    if (-not $algo) { return $false }
    $x = $Hash.Trim().ToLower()
    if ($index.ContainsKey($x)) {
        $e = $index[$x]
        if (-not $e.Sources.Contains($Source)) { [void] $e.Sources.Add($Source) }
        if ([string]::IsNullOrWhiteSpace($e.Pilote) -and $Pilote) { $e.Pilote = Protect-Champ $Pilote }
        if ($Hvci) { $e.Hvci = $true }
    }
    else {
        $set = New-Object System.Collections.Generic.HashSet[string]
        [void] $set.Add($Source)
        $index[$x] = [pscustomobject]@{
            Algo    = $algo
            Pilote  = (Protect-Champ $Pilote)
            Hvci    = $Hvci
            Sources = $set
        }
    }
    return $true
}

function Get-Prop {
    # Lecture défensive d'une propriété d'objet, insensible à la casse, sur
    # une liste de noms candidats. Renvoie '' si aucune ne convient.
    param($Obj, [string[]] $Noms)
    if ($null -eq $Obj) { return '' }
    foreach ($n in $Noms) {
        $p = $Obj.PSObject.Properties[$n]
        if ($p -and $p.Value) { return [string] $p.Value }
    }
    return ''
}

# ===========================================================================
#  SOURCE 1 — LOLDrivers (loldrivers.io)
# ===========================================================================

function Import-Loldrivers {
    Write-Host '[*] LOLDrivers...' -ForegroundColor Cyan
    $avant = $index.Count
    # API CSV plutôt que JSON : le drivers.json est volumineux et bute sur la
    # limite MaxJsonLength de ConvertFrom-Json sous Windows PowerShell 5.1. Le
    # CSV n'a pas cette limite. On sélectionne les colonnes d'empreinte de
    # FICHIER (md5/sha1/sha256) en EXCLUANT imphash et authentihash, qui ne
    # sont pas des empreintes de fichier et fausseraient la correspondance.
    $brut = Invoke-WebRequest -Uri $UrlLoldrivers -UseBasicParsing -TimeoutSec $TimeoutSec
    $octets = $brut.Content.Length
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('lol_' + [guid]::NewGuid().ToString('N') + '.csv')
    [IO.File]::WriteAllText($tmp, $brut.Content, [Text.Encoding]::UTF8)
    $nbLignes = 0
    try {
        $lignes = Import-Csv -LiteralPath $tmp
        $nbLignes = @($lignes).Count
        # Repérage des colonnes une seule fois, sur le premier enregistrement.
        $colsHash = @(); $colNom = $null; $colHvci = $null
        if ($nbLignes -gt 0) {
            foreach ($p in $lignes[0].PSObject.Properties) {
                $n = $p.Name
                if ($n -match '(?i)(md5|sha1|sha256)' -and $n -notmatch '(?i)(imphash|authentihash|rich|import)') { $colsHash += $n }
                if (-not $colNom  -and $n -match '(?i)filename') { $colNom = $n }
                if (-not $colHvci -and $n -match '(?i)hvci')     { $colHvci = $n }
            }
        }
        foreach ($l in $lignes) {
            $nom = ''; if ($colNom) { $nom = [string] $l.$colNom }
            $hvci = $false; if ($colHvci) { $hvci = ([string] $l.$colHvci -match '(?i)true|oui|yes') }
            foreach ($c in $colsHash) {
                $val = [string] $l.$c
                # Une cellule peut contenir plusieurs empreintes séparées.
                foreach ($h in ($val -split '[,;\s]+')) {
                    if ($h) { [void] (Add-Empreinte -Hash $h -Pilote $nom -Hvci $hvci -Source 'loldrivers') }
                }
            }
        }
    }
    finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    $ajout = $index.Count - $avant
    $statsSource['loldrivers'] = $ajout
    Write-Host ('    ' + $octets + ' octets, ' + $nbLignes + ' enregistrement(s), ' + $ajout + ' empreinte(s) nouvelle(s)') -ForegroundColor DarkGray
    if ($nbLignes -gt 0 -and $ajout -eq 0) {
        Write-Warning '    LOLDrivers : enregistrements lus mais aucune empreinte extraite — noms de colonnes de hachage inattendus.'
    }
}

# ===========================================================================
#  SOURCE 1bis — Drapeau HVCI (fichier séparé du repo LOLDrivers)
# ===========================================================================

function Import-HvciFlags {
    Write-Host '[*] Drapeau HVCI (hvci_drivers.csv)...' -ForegroundColor Cyan
    # Chaque ligne de ce fichier est un pilote qui se charge MALGRÉ HVCI actif.
    # On pose donc le drapeau sur toute empreinte correspondante déjà présente,
    # et on l'ajoute si elle manque. Mêmes colonnes de hachage que LOLDrivers,
    # imphash exclu.
    $brut = Invoke-WebRequest -Uri $UrlHvci -UseBasicParsing -TimeoutSec $TimeoutSec
    $octets = $brut.Content.Length
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('hvci_' + [guid]::NewGuid().ToString('N') + '.csv')
    [IO.File]::WriteAllText($tmp, $brut.Content, [Text.Encoding]::UTF8)
    $nbFlags = 0; $nbLignes = 0
    try {
        $lignes = Import-Csv -LiteralPath $tmp
        $nbLignes = @($lignes).Count
        $colsHash = @(); $colNom = $null
        if ($nbLignes -gt 0) {
            foreach ($p in $lignes[0].PSObject.Properties) {
                $n = $p.Name
                if ($n -match '(?i)(md5|sha1|sha256)' -and $n -notmatch '(?i)(imphash|authentihash|rich|import)') { $colsHash += $n }
                if (-not $colNom -and $n -match '(?i)filename') { $colNom = $n }
            }
        }
        foreach ($l in $lignes) {
            $nom = ''; if ($colNom) { $nom = [string] $l.$colNom }
            foreach ($c in $colsHash) {
                foreach ($h in ([string] $l.$c -split '[,;\s]+')) {
                    if (-not $h) { continue }
                    $algo = Test-Empreinte $h
                    if (-not $algo) { continue }
                    $x = $h.Trim().ToLower()
                    if ($index.ContainsKey($x)) {
                        if (-not $index[$x].Hvci) { $index[$x].Hvci = $true; $nbFlags++ }
                    }
                    else {
                        [void] (Add-Empreinte -Hash $h -Pilote $nom -Hvci $true -Source 'loldrivers')
                        $nbFlags++
                    }
                }
            }
        }
    }
    finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    Write-Host ('    ' + $octets + ' octets, ' + $nbLignes + ' enregistrement(s), ' + $nbFlags + ' empreinte(s) marquée(s) HVCI') -ForegroundColor DarkGray
}

# ===========================================================================
#  SOURCE 2 — Blocklist Microsoft (transformée en empreintes de fichier)
# ===========================================================================

function Import-MsBlocklist {
    Write-Host '[*] Blocklist Microsoft...' -ForegroundColor Cyan
    $avant = $index.Count
    # On tente d'abord le CSV (léger, insensible à la limite JSON de PS 5.1),
    # puis le JSON en repli. La blocklist est bien plus petite que LOLDrivers,
    # donc le JSON reste lisible sous 5.1 si le CSV n'existe pas.
    $contenu = $null; $estJson = $false
    try { $contenu = (Invoke-WebRequest -Uri $UrlMsBlocklistCsv -UseBasicParsing -TimeoutSec $TimeoutSec).Content }
    catch {
        $contenu = (Invoke-WebRequest -Uri $UrlMsBlocklistJson -UseBasicParsing -TimeoutSec $TimeoutSec).Content
        $estJson = $true
    }
    $octets = $contenu.Length
    $nbLignes = 0
    if ($estJson) {
        $data = $contenu | ConvertFrom-Json
        foreach ($l in @($data)) {
            $nbLignes++
            $h = Get-Prop $l @('FileHash', 'SHA256', 'Sha256', 'FileSHA256')
            $nom = Get-Prop $l @('FileName', 'Filename', 'FriendlyName', 'DriverName')
            if ($h) { [void] (Add-Empreinte -Hash $h -Pilote $nom -Hvci $false -Source 'ms-blocklist') }
        }
    }
    else {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('ms_blocklist_' + [guid]::NewGuid().ToString('N') + '.csv')
        [IO.File]::WriteAllText($tmp, $contenu, [Text.Encoding]::UTF8)
        try {
            $lignes = Import-Csv -LiteralPath $tmp
            $nbLignes = @($lignes).Count
            foreach ($l in $lignes) {
                $h = Get-Prop $l @('FileHash', 'SHA256', 'Sha256', 'FileSHA256')
                $nom = Get-Prop $l @('FileName', 'Filename', 'FriendlyName', 'DriverName')
                if ($h) { [void] (Add-Empreinte -Hash $h -Pilote $nom -Hvci $false -Source 'ms-blocklist') }
            }
        }
        finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
    $ajout = $index.Count - $avant
    $statsSource['ms-blocklist'] = $ajout
    Write-Host ('    ' + $octets + ' octets, ' + $nbLignes + ' enregistrement(s), ' + $ajout + ' empreinte(s) nouvelle(s)') -ForegroundColor DarkGray
    if ($nbLignes -gt 0 -and $ajout -eq 0) {
        Write-Warning '    Blocklist Microsoft : enregistrements lus mais aucune empreinte extraite — colonne FileHash absente ou renommée.'
    }
}

# ===========================================================================
#  SOURCE 3 — MalwareBazaar (abuse.ch) — OPTIONNEL, nécessite une clé
# ===========================================================================

function Import-MalwareBazaar {
    Write-Host '[*] MalwareBazaar (optionnel)...' -ForegroundColor Cyan
    if ([string]::IsNullOrWhiteSpace($CleMalwareBazaar)) {
        Write-Warning '    Clé absente (AGILLY_MB_KEY) : source ignorée.'
        return
    }
    $avant = $index.Count
    $entetes = @{ 'Auth-Key' = $CleMalwareBazaar }
    foreach ($tag in $TagsMalwareBazaar) {
        try {
            $corps = @{ query = 'get_taginfo'; tag = $tag; limit = '1000' }
            $rep = Invoke-RestMethod -Uri $UrlMalwareBazaar -Method Post -Body $corps -Headers $entetes -TimeoutSec $TimeoutSec
            if ($rep.query_status -ne 'ok') { continue }
            foreach ($s in @($rep.data)) {
                # Ne retenir que les pilotes noyau.
                $ft = [string] $s.file_type
                if ($ft -ne 'sys') { continue }
                $nom = [string] $s.file_name
                foreach ($champ in @('sha256_hash', 'sha1_hash', 'md5_hash')) {
                    $h = [string] $s.$champ
                    if ($h) { [void] (Add-Empreinte -Hash $h -Pilote $nom -Hvci $false -Source 'malwarebazaar') }
                }
            }
        }
        catch { Write-Warning ("    tag '" + $tag + "' : " + $_.Exception.Message) }
    }
    $ajout = $index.Count - $avant
    $statsSource['malwarebazaar'] = $ajout
    Write-Host ("    empreintes nouvelles : " + $ajout) -ForegroundColor DarkGray
}

# ===========================================================================
#  COLLECTE
# ===========================================================================

Write-Host ''
Write-Host '=== Collecte des empreintes de pilotes vulnérables ===' -ForegroundColor White
Write-Host ('    PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor DarkGray
Write-Host ''

$erreurs = @()
if ($ActiverLoldrivers)   { try { Import-Loldrivers }   catch { $erreurs += 'LOLDrivers : ' + $_.Exception.Message } }
if ($ActiverLoldrivers)   { try { Import-HvciFlags }    catch { $erreurs += 'Drapeau HVCI : ' + $_.Exception.Message } }
if ($ActiverMsBlocklist)  { try { Import-MsBlocklist }  catch { $erreurs += 'Blocklist Microsoft : ' + $_.Exception.Message } }
if ($ActiverMalwareBazaar){ try { Import-MalwareBazaar }catch { $erreurs += 'MalwareBazaar : ' + $_.Exception.Message } }

foreach ($e in $erreurs) { Write-Warning $e }

# Récapitulatif d'apport, affiché DANS TOUS LES CAS (y compris échec) pour que
# le diagnostic reste lisible même quand rien n'est écrit.
Write-Host ''
Write-Host '  Apport par source :' -ForegroundColor White
if ($statsSource.Count -eq 0) { Write-Host '    (aucune source exécutée)' -ForegroundColor DarkGray }
foreach ($k in $statsSource.Keys) { Write-Host ('    ' + $k + ' : ' + $statsSource[$k]) }

# ===========================================================================
#  GARDE-FOU ET ÉCRITURE
# ===========================================================================

Write-Host ''
# IMPORTANT : ne jamais appeler « exit » ici. Lancé en session interactive
# (.\script.ps1), exit ferme la fenêtre PowerShell et détruit le diagnostic
# affiché. On signale et on s'arrête proprement par un if/else, sans quitter
# l'hôte. Un appelant automatisé peut tester l'existence du fichier de sortie.
if ($index.Count -lt $MinimumEmpreintes) {
    Write-Warning ('Collecte incomplète : ' + $index.Count + ' empreinte(s) uniques, minimum attendu ' + $MinimumEmpreintes + '.')
    Write-Warning 'Aucun fichier écrit : au moins une source a échoué ou a renvoyé un schéma inattendu.'
    Write-Warning 'Une source à 0 empreinte avec des octets reçus = schéma distant changé ; à 0 octet ou en erreur = réseau/proxy.'
}
else {
    if (-not (Test-Path -LiteralPath $DossierSortie)) {
        New-Item -ItemType Directory -Path $DossierSortie -Force | Out-Null
    }
    # Nom HORODATÉ : chaque exécution produit un fichier neuf. Un nom fixe
    # réécrit à chaque run bute sur le verrou d'Excel (si le CSV est ouvert)
    # ou de OneDrive (synchro en cours), d'où l'IOException « fichier en cours
    # d'utilisation ». Un nom neuf n'est tenu par personne.
    $horo = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $nomHoro = [IO.Path]::GetFileNameWithoutExtension($NomFichier) + '_' + $horo + '.csv'
    $chemin = Join-Path $DossierSortie $nomHoro

    # Écriture manuelle : entête non quotée « algo;empreinte;... » indispensable
    # à la détection de format côté audit (Export-Csv quoterait et casserait cela).
    $sb = New-Object System.Text.StringBuilder
    [void] $sb.AppendLine('algo;empreinte;pilote;hvci;sources')
    foreach ($h in ($index.Keys | Sort-Object)) {
        $e = $index[$h]
        $hvci = ''
        if ($e.Hvci) { $hvci = 'CHARGE_MALGRE_HVCI' }
        $src = (($e.Sources | Sort-Object) -join ',')
        [void] $sb.AppendLine($e.Algo + ';' + $h + ';' + $e.Pilote + ';' + $hvci + ';' + $src)
    }

    # UTF-8 AVEC BOM. Écriture dans un temporaire puis déplacement, avec
    # réessais : couvre un verrou transitoire (antivirus, synchro OneDrive).
    $enc = New-Object System.Text.UTF8Encoding($true)
    $tmpOut = Join-Path $DossierSortie ('.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $ecrit = $false
    try {
        [IO.File]::WriteAllText($tmpOut, $sb.ToString(), $enc)
        for ($essai = 1; $essai -le 4; $essai++) {
            try {
                if (Test-Path -LiteralPath $chemin) { [IO.File]::Delete($chemin) }
                [IO.File]::Move($tmpOut, $chemin)
                $ecrit = $true
                break
            }
            catch {
                if ($essai -eq 4) { throw }
                Start-Sleep -Seconds 2
            }
        }
    }
    catch {
        Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue
        Write-Warning ('Écriture impossible : ' + $_.Exception.Message)
        Write-Warning 'Fichier verrouillé. Fermer le CSV s''il est ouvert (Excel), ou pointer $DossierSortie vers un dossier hors OneDrive (ex. C:\ProgramData\AGILLY-Empreintes), puis relancer.'
    }

    if ($ecrit) {
        $sha = (Get-FileHash -LiteralPath $chemin -Algorithm SHA256).Hash.ToLower()

        # Empreinte écrite à côté du CSV : un consommateur externe doit pouvoir
        # vérifier l'intégrité sans recopier une valeur depuis une console.
        # Format « empreinte  nom-de-fichier », compatible sha256sum.
        $cheminSha = $chemin + '.sha256'
        try {
            $ligneSha = $sha + '  ' + [IO.Path]::GetFileName($chemin)
            [IO.File]::WriteAllText($cheminSha, $ligneSha, (New-Object System.Text.UTF8Encoding($false)))
        }
        catch {
            $cheminSha = ''
            Write-Warning ('Empreinte non écrite sur disque : ' + $_.Exception.Message)
        }

        # Ventilation par algorithme
        $parAlgo = @{ MD5 = 0; SHA1 = 0; SHA256 = 0 }
        foreach ($h in $index.Keys) { $parAlgo[$index[$h].Algo]++ }
        $nbHvci = @($index.Values | Where-Object { $_.Hvci }).Count

        Write-Host ''
        Write-Host '=== Résultat ===' -ForegroundColor White
        Write-Host ('  Empreintes uniques : ' + $index.Count)
        Write-Host ('    SHA256 : ' + $parAlgo['SHA256'] + '   SHA1 : ' + $parAlgo['SHA1'] + '   MD5 : ' + $parAlgo['MD5'])
        Write-Host ('    dont « se charge malgré HVCI » : ' + $nbHvci)
        Write-Host ''
        Write-Host ('  Fichier : ' + $chemin) -ForegroundColor Green
        Write-Host ('  SHA256  : ' + $sha) -ForegroundColor Green
        if ($cheminSha -ne '') { Write-Host ('  Empreinte : ' + $cheminSha) -ForegroundColor Green }
        Write-Host ''
        Write-Host '  Copier ce fichier à côté du script d''audit sous le nom AGILLY_LOLDrivers_Empreintes.csv,' -ForegroundColor DarkGray
        Write-Host '  reporter l''empreinte SHA256 ci-dessus dans $LolDriversSha256 de l''audit et au §6 du mémo,' -ForegroundColor DarkGray
        Write-Host '  et préserver l''encodage UTF-8 avec BOM.' -ForegroundColor DarkGray
    }
}

