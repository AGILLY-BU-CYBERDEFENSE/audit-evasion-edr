# ===========================================================================
#  AGILLY Cyberdéfense
#  Audit du socle Windows face aux vecteurs d'évasion EDR
#  Version 1.0
# ---------------------------------------------------------------------------
#  PORTÉE DE CE CONTRÔLE, À LIRE AVANT INTERPRÉTATION
#
#  Les techniques de neutralisation d'agent reposent toutes sur des
#  conditions préalables : des privilèges d'administration locale, la
#  capacité à charger un pilote dans le noyau, l'absence de politique
#  d'intégrité du code, la possibilité d'arrêter un service, ou l'absence
#  de télémétrie transmise à un tiers.
#
#  Ce script mesure ces conditions. Chacune qui disparaît augmente le coût
#  de l'attaque et la probabilité qu'elle soit détectée.
#
#  Ce qu'il ne démontre pas : qu'un agent résisterait à une tentative
#  ciblée. HVCI n'empêche pas la manipulation de structures noyau, la liste
#  de blocage Microsoft ne couvre qu'une fraction des pilotes vulnérables
#  connus, et la protection anti-sabotage ne résiste pas à une terminaison
#  initiée depuis le noyau. Établir la résistance effective relève d'un
#  test contrôlé en environnement isolé, qui est un exercice distinct.
#
#  HYPOTHÈSE DE VALIDITÉ : ce constat suppose que le système d'exploitation
#  n'est pas déjà compromis. Chaque contrôle lit l'état de la machine par les
#  interfaces que Windows lui-même expose, registre, WMI, gestionnaire de
#  services, journaux d'événements, variables de firmware relayées par le
#  noyau. Autrement dit, c'est le système audité qui rend son propre verdict.
#  Cela vaut A FORTIORI pour les contrôles d'intégrité noyau : l'état de HVCI,
#  de Credential Guard ou de la protection LSA est rapporté à travers le noyau
#  lui-même. Un attaquant qui le contrôle peut le faire répondre « actif ».
#  Ce n'est pas une faiblesse de l'outil mais la limite de tout audit en ligne
#  sur un système vivant : établir qu'une machine n'est pas compromise relève
#  d'une analyse hors ligne ou d'une télémétrie collectée en dehors d'elle.
#  Cet outil répond à « mon socle est-il durci ? », jamais à
#  « ai-je été compromis ? ».
# ---------------------------------------------------------------------------
#  NATURE : LECTURE SEULE DU SYSTÈME.
#    - Aucune clé de registre, aucun service, aucune politique n'est modifié.
#    - Aucune préférence de session PowerShell n'est altérée.
#    - Aucun appel réseau n'est émis. Aucune donnée ne quitte la machine.
#    - Les seules écritures sont celles des livrables produits par l'audit,
#      dans un dossier du profil utilisateur (jamais dans un répertoire
#      système), dont le chemin est affiché en fin d'exécution.
#
#  LIVRABLES GÉNÉRÉS AUTOMATIQUEMENT :
#    - un rapport HTML autonome, destiné au client
#    - un export CSV, destiné à la consolidation interne
#  Destination par défaut, dans cet ordre de préférence :
#    Bureau\AGILLY-Audits, puis Documents\AGILLY-Audits, puis
#    %TEMP%\AGILLY-Audits, puis %PUBLIC%\AGILLY-Audits
#
#  Le rapport HTML est autonome : styles embarqués, aucun fichier joint.
#  Pour un PDF, l'imprimer depuis le navigateur (Ctrl+P, destination
#  « Enregistrer au format PDF »). La mise en page est prévue pour cela.
#
#  EXÉCUTION : deux modes supportés.
#    1) Coller l'intégralité du script dans une console PowerShell élevée.
#    2) Enregistrer en .ps1 puis :
#       powershell -ExecutionPolicy Bypass -File .\Audit-SocleEvasionEDR-v1.ps1
#
#  PRÉREQUIS : Windows 10 / Server 2016 ou ultérieur, PowerShell 5.1.
#  Sur systèmes antérieurs, certains contrôles retournent INDÉTERMINÉ.
#
#  ENCODAGE : conserver le fichier en UTF-8 AVEC BOM.
#
#  CODES DE SORTIE (mode fichier uniquement) :
#    0 = aucun écart      1 = écarts faibles/moyens
#    2 = écart élevé      3 = écart critique
#    4 = audit non concluant (session non élevée, ou couverture trop faible
#        pour qu'un « aucun écart » ait un sens : à ne PAS lire comme vert)
#    5 = erreur d'exécution empêchant l'audit
#
#  PRIORITÉ : un écart avéré prime sur le caractère non concluant. Un poste à
#  faible couverture MAIS portant un écart critique remonte en 3, pas en 4.
#  En consolidation de parc, lire TOUJOURS la colonne « Couverture » de
#  l'export avec le code de sortie : un code 0/1/2/3 sur une couverture basse
#  reste un audit partiel.
# ===========================================================================


# ===========================================================================
#  PARAMÉTRAGE
# ===========================================================================

# Génération des livrables. Activée par défaut.
$GenererHtml = $true    # rapport client, autonome
$GenererCsv  = $true    # export de consolidation interne

# Dossier de destination des livrables.
# Laisser vide pour une sélection automatique dans un emplacement non
# sensible du profil utilisateur. Le dossier est créé s'il n'existe pas.
# Exemple d'usage MSSP : '\\serveur\partage\Audits\Socle'
$DossierRapports = ''

# Ouvrir automatiquement le rapport à la fin de l'exécution.
$OuvrirRapport = $false

# Inventaire des pilotes noyau tiers (signature + empreinte SHA256).
# Ajoute 20 à 60 secondes selon le parc logiciel installé.
$ScanDrivers = $true

# Liste locale d'empreintes de pilotes vulnérables connus.
# Format attendu : CSV point-virgule avec en-tête
#   algo;empreinte;pilote;hvci;sources
# Le fichier AGILLY_LOLDrivers_Empreintes.csv fourni avec ce script est
# détecté automatiquement s'il se trouve à côté du script ou dans le
# dossier des livrables. Renseigner cette variable pour imposer un chemin,
# par exemple un partage interne : '\\serveur\partage\Outils\loldrivers.csv'
# Tout export LOLDrivers brut (.csv, .json, .txt) reste accepté : le script
# bascule alors sur une extraction par motif, limitée au SHA256.
$LolDriversPath = ''

# Empreinte SHA256 attendue du fichier de référence. Renseignée, elle est
# vérifiée avant usage : sans cela, un fichier vidé ou tronqué ferait
# ressortir tous les pilotes comme sains, sans que rien ne le signale.
#
# Laissée vide, elle est reprise automatiquement du fichier « .sha256 »
# adjacent à la liste, s'il existe (format sha256sum ou empreinte nue).
# PORTÉE DE CETTE VÉRIFICATION : elle atteste que la liste n'a pas été
# tronquée ni corrompue au transport. Elle n'atteste PAS son authenticité, 
# qui remplace le CSV remplace aussi le .sha256 posé à côté. Pour une
# vérification d'authenticité, renseigner ici en dur l'empreinte publiée sur
# le dépôt, ou passer AGILLY_LOLSHA256 depuis l'outil de déploiement.
$LolDriversSha256 = ''

# Nombre d'entrées minimal attendu. En deçà, la liste est considérée comme
# tronquée et la comparaison est déclarée non concluante.
$LolDriversMinimum = 1000

# Couverture d'audit en deçà de laquelle un « aucun écart » ne doit pas être
# interprété comme un état sain : trop de contrôles n'ont pas pu être évalués.
# Sous ce seuil, le code de sortie est forcé à 4 (audit non concluant).
$CouvertureMinimale = 60

# Surcharge par variables d'environnement (usage MSSP / RMM). Utilisable dans
# les DEUX modes d'exécution, contrairement à param() qui casse le collage en
# console. Une variable définie l'emporte sur la valeur ci-dessus.
#   AGILLY_DOSSIER   -> $DossierRapports
#   AGILLY_LOLPATH   -> $LolDriversPath
#   AGILLY_LOLSHA256 -> $LolDriversSha256
#   AGILLY_NOHTML=1  -> désactive le rapport HTML
#   AGILLY_NOCSV=1   -> désactive l'export CSV
if ($env:AGILLY_DOSSIER)   { $DossierRapports  = $env:AGILLY_DOSSIER }
if ($env:AGILLY_LOLPATH)   { $LolDriversPath   = $env:AGILLY_LOLPATH }
if ($env:AGILLY_LOLSHA256) { $LolDriversSha256 = $env:AGILLY_LOLSHA256 }
if ($env:AGILLY_NOHTML -eq '1') { $GenererHtml = $false }
if ($env:AGILLY_NOCSV  -eq '1') { $GenererCsv  = $false }


# ===========================================================================
#  CONSTANTES
# ===========================================================================

$ST_OK   = 'CONFORME'
$ST_PRES = 'CONFORME (PRÉSUMÉ)'
$ST_KO   = 'NON CONFORME'
$ST_UNK  = 'INDÉTERMINÉ'
$ST_NA   = 'NON APPLICABLE'
$ST_CONF = 'CONFIGURÉ (NON ACTIF)'
$ST_INFO = 'INFORMATION'
# Contrôle qui ne peut être tranché que depuis la console de l'éditeur (agent
# tiers). Distinct d'INDÉTERMINÉ : ce n'est pas un échec de lecture de notre
# fait, et il ne doit pas pénaliser la couverture d'audit ni faire croire à
# une posture plus faible qu'un poste équivalent sous Defender.
$ST_CONSOLE = 'À VÉRIFIER EN CONSOLE'
# Signal d'historique demandant une corrélation que le script ne peut pas
# faire : il ignore les fenêtres de maintenance déclarées et le cycle de mise
# à jour des agents. Un tel signal est un point de triage, pas un écart de
# configuration constaté. Il est donc restitué, mais il ne pèse ni sur le
# score ni sur le plafonnement : faire chuter une note sur un fait que les
# données ne permettent pas d'établir serait rendre un verdict non fondé.
$ST_TRI = 'À TRIER'

$CR_CRIT = 'Critique'
$CR_ELEV = 'Élevée'
$CR_MOY  = 'Moyenne'
$CR_FAIB = 'Faible'
$CR_INFO = 'Information'

$POIDS = @{}
$POIDS[$CR_CRIT] = 5
$POIDS[$CR_ELEV] = 3
$POIDS[$CR_MOY]  = 2
$POIDS[$CR_FAIB] = 1
$POIDS[$CR_INFO] = 0

# ---------------------------------------------------------------------------
#  CORRÉLATION MITRE ATT&CK
#  Rattachement indicatif de chaque contrôle à la ou aux techniques qu'il
#  contraint ou dont il détecte la trace. La clé est le NOM EXACT du contrôle :
#  un contrôle ajouté sans entrée ici sort simplement sans technique, il n'y a
#  aucune rupture. Le rattachement qualifie le contrôle, pas un constat : il ne
#  signifie pas que la technique a été observée sur la machine auditée.
# ---------------------------------------------------------------------------

$MITRE = @{}
# Socle firmware
$MITRE['Secure Boot']                                          = 'T1542.001, T1542.003'
$MITRE['Options de démarrage du noyau']                        = 'T1553.006, T1562.001'
# Intégrité noyau
$MITRE['Sécurité basée sur la virtualisation (VBS)']           = 'T1068, T1547.006'
$MITRE['Intégrité du code (HVCI)']                             = 'T1068, T1547.006'
$MITRE['Credential Guard']                                     = 'T1003.001'
$MITRE['Protection LSA (RunAsPPL)']                            = 'T1003.001'
$MITRE['Protection DMA du noyau']                              = 'T1200'
# Anti-BYOVD
$MITRE['Liste de blocage des pilotes vulnérables']             = 'T1068, T1547.006'
$MITRE['Politique d''intégrité du code (WDAC / App Control)']  = 'T1553.006, T1547.006'
$MITRE['Règle ASR pilotes vulnérables']                        = 'T1068'
$MITRE['Inventaire des pilotes noyau tiers']                   = 'T1547.006'
$MITRE['Inventaire des minifiltres (Filter Manager)']          = 'T1547.006'
$MITRE['Correspondance avec les pilotes vulnérables connus']   = 'T1068, T1547.006'
$MITRE['Minifiltres vulnérables (hors inventaire de service)'] = 'T1068, T1547.006'
$MITRE['Pilotes à signature non valide']                       = 'T1553.002, T1553.006'
$MITRE['Pilotes en exécution sans fichier sur disque']         = 'T1014, T1070.004'
$MITRE['Minifiltres en exécution sans fichier sur disque']     = 'T1014, T1070.004'
$MITRE['Fraîcheur de la liste d''empreintes']                  = 'T1068'
# Intégrité de l'agent
$MITRE['Agents de sécurité détectés']                          = 'T1562.001'
$MITRE['État des services de sécurité']                        = 'T1562.001'
$MITRE['Protection temps réel']                                = 'T1562.001'
$MITRE['Protection anti-sabotage']                             = 'T1562.001'
$MITRE['Mode d''exécution Defender']                           = 'T1562.001'
$MITRE['Fraîcheur des signatures']                             = 'T1562.001'
$MITRE['Démarrage en mode sans échec']                         = 'T1562.009'
# Télémétrie
$MITRE['Rattachement à une console (MDE)']                     = 'T1562.001'
$MITRE['Remontée effective vers la console (MDE)']             = 'T1562.001'
$MITRE['Exclusions antivirus']                                 = 'T1562.001'
$MITRE['Fournisseurs AMSI enregistrés']                        = 'T1562.001, T1059.001'
$MITRE['Journalisation ScriptBlock PowerShell']                = 'T1562.002'
$MITRE['Journalisation des modules PowerShell']                = 'T1562.002'
$MITRE['Transcription PowerShell']                             = 'T1562.002'
$MITRE['Moteur PowerShell v2']                                 = 'T1059.001, T1562.001'
$MITRE['Rétention du journal Sécurité']                        = 'T1070.001'
# Historique
$MITRE['Arrêts de services de sécurité (30 j)']                = 'T1562.001'
$MITRE['Désactivations de protection Defender (30 j)']         = 'T1562.001'
$MITRE['Installation de pilotes noyau (30 j)']                 = 'T1547.006'
$MITRE['Refus de chargement de pilotes (30 j)']                = 'T1068, T1553.006'
$MITRE['Intégrité des journaux (effacement, 30 j)']            = 'T1070.001'
$MITRE['Collecteur indépendant de l''agent']                   = 'T1070.001, T1562.002'
# Privilèges
$MITRE['Composition du groupe Administrateurs locaux']         = 'T1078.003'
$MITRE['Rotation du mot de passe administrateur local (LAPS)'] = 'T1078.003'
$MITRE['Contrôle de compte d''utilisateur (UAC)']              = 'T1548.002'
# Réduction de surface
$MITRE['Posture ASR globale']                                  = 'T1562.001'
$MITRE['ASR, exécutables peu répandus (prévalence)']          = 'T1204.002'

$VERSION_SCRIPT = '1.0'

$findings = New-Object System.Collections.ArrayList
$erreursExecution = New-Object System.Collections.ArrayList


# ===========================================================================
#  FONCTIONS UTILITAIRES
# ===========================================================================

function Add-Finding {
    param(
        [string] $Axe,
        [string] $Controle,
        [string] $Etat,
        [string] $Criticite,
        [string] $Detail,
        [string] $Recommandation
    )
    $o = New-Object PSObject
    Add-Member -InputObject $o -MemberType NoteProperty -Name Axe -Value $Axe
    Add-Member -InputObject $o -MemberType NoteProperty -Name Controle -Value $Controle
    $tech = ''
    if ($MITRE.ContainsKey($Controle)) { $tech = $MITRE[$Controle] }
    Add-Member -InputObject $o -MemberType NoteProperty -Name Technique -Value $tech
    Add-Member -InputObject $o -MemberType NoteProperty -Name Etat -Value $Etat
    Add-Member -InputObject $o -MemberType NoteProperty -Name Criticite -Value $Criticite
    Add-Member -InputObject $o -MemberType NoteProperty -Name Detail -Value $Detail
    Add-Member -InputObject $o -MemberType NoteProperty -Name Recommandation -Value $Recommandation
    $null = $findings.Add($o)
}

function Add-Erreur {
    param([string] $Contexte, [string] $Message)
    $o = New-Object PSObject
    Add-Member -InputObject $o -MemberType NoteProperty -Name Contexte -Value $Contexte
    Add-Member -InputObject $o -MemberType NoteProperty -Name Message -Value $Message
    $null = $erreursExecution.Add($o)
}

function Get-RegValue {
    param([string] $Path, [string] $Name)
    $r = New-Object PSObject
    Add-Member -InputObject $r -MemberType NoteProperty -Name Found -Value $false
    Add-Member -InputObject $r -MemberType NoteProperty -Name Value -Value $null
    Add-Member -InputObject $r -MemberType NoteProperty -Name Error -Value $null
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        if ($_.Exception -is [System.Security.SecurityException]) {
            $r.Error = 'Accès refusé (élévation requise).'
        }
        elseif ($_.CategoryInfo.Category -eq 'ObjectNotFound') {
            $r.Error = $null
        }
        else {
            $r.Error = $_.Exception.Message
        }
        return $r
    }
    if ($k.GetValueNames() -contains $Name) {
        $r.Found = $true
        $r.Value = $k.GetValue($Name)
    }
    return $r
}

function Test-RegDword {
    # Renvoie $true si la valeur existe et est comprise dans $Attendus
    param([string] $Path, [string] $Name, [int[]] $Attendus)
    $v = Get-RegValue -Path $Path -Name $Name
    if (-not $v.Found) { return $false }
    try { return ($Attendus -contains ([int] $v.Value)) } catch { return $false }
}

function Test-JournalisationPS {
    # La journalisation PowerShell se configure à deux endroits : par
    # stratégie de groupe, et localement. Ne tester que le chemin Policies
    # produit un faux négatif sur toute machine configurée manuellement.
    param([string] $SousCle, [string] $Valeur)
    $r = New-Object PSObject
    Add-Member -InputObject $r -MemberType NoteProperty -Name Actif -Value $false
    Add-Member -InputObject $r -MemberType NoteProperty -Name Source -Value ''
    $emplacements = @()
    $emplacements += , @('stratégie de groupe', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\' + $SousCle)
    $emplacements += , @('configuration locale', 'HKLM:\SOFTWARE\Microsoft\Windows\PowerShell\' + $SousCle)
    foreach ($e in $emplacements) {
        if (Test-RegDword -Path $e[1] -Name $Valeur -Attendus @(1)) {
            $r.Actif = $true
            $r.Source = $e[0]
            break
        }
    }
    return $r
}

function Resolve-DriverPath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim().Trim('"')
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '^[Ss]ystem32\\') {
        $p = Join-Path $env:SystemRoot $p
    }
    if ($p -notmatch '^[A-Za-z]:\\') {
        $p = Join-Path $env:SystemRoot $p
    }
    return $p
}

function Get-AdminsLocaux {
    # Deux implémentations : cmdlet native, puis repli WinNT pour les
    # machines présentant des SID orphelins (changement de domaine).
    $res = New-Object PSObject
    Add-Member -InputObject $res -MemberType NoteProperty -Name Membres -Value @()
    Add-Member -InputObject $res -MemberType NoteProperty -Name Methode -Value ''
    Add-Member -InputObject $res -MemberType NoteProperty -Name Error -Value $null

    try {
        $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $res.Membres = @($m | ForEach-Object { $_.Name })
        $res.Methode = 'Get-LocalGroupMember'
        return $res
    }
    catch {
        $res.Error = $_.Exception.Message
    }

    try {
        $grp = [ADSI] 'WinNT://./Administrators,group'
        $noms = @()
        foreach ($membre in $grp.Invoke('Members')) {
            try {
                $noms += $membre.GetType().InvokeMember('Name', 'GetProperty', $null, $membre, $null)
            }
            catch { }
        }
        if ($noms.Count -gt 0) {
            $res.Membres = $noms
            $res.Methode = 'ADSI WinNT (repli)'
            $res.Error = $null
        }
    }
    catch {
        $res.Error = $res.Error + ' | Repli ADSI : ' + $_.Exception.Message
    }
    return $res
}

function Get-Evenements {
    # Lecture bornée d'un journal d'événements.
    # Distingue explicitement « aucun événement » d'une erreur d'accès :
    # confondre les deux produirait un faux constat de sécurité.
    param(
        [string]   $Journal,
        [int[]]    $Ids,
        [datetime] $Depuis,
        [string]   $Fournisseur = '',
        [int]      $Max = 4000
    )
    $r = New-Object PSObject
    Add-Member -InputObject $r -MemberType NoteProperty -Name Evenements -Value @()
    Add-Member -InputObject $r -MemberType NoteProperty -Name Erreur -Value $null
    # Tronque = le plafond Max a été atteint : les événements les plus anciens
    # de la fenêtre demandée peuvent manquer. Confondre « rien trouvé » avec
    # « plafond atteint » produirait un faux « aucun arrêt sur 30 jours ».
    Add-Member -InputObject $r -MemberType NoteProperty -Name Tronque -Value $false
    $filtre = @{ LogName = $Journal; Id = $Ids; StartTime = $Depuis }
    if ($Fournisseur -ne '') { $filtre['ProviderName'] = $Fournisseur }
    try {
        $r.Evenements = @(Get-WinEvent -FilterHashtable $filtre -MaxEvents $Max -ErrorAction Stop)
        if ($r.Evenements.Count -ge $Max) { $r.Tronque = $true }
    }
    catch {
        $m = $_.Exception.Message
        if ($m -match 'No events were found|Aucun .v.nement|did not find any events|introuvable') {
            $r.Evenements = @()
        }
        else { $r.Erreur = $m }
    }
    return $r
}

function Protect-Html {
    param([string] $Texte)
    if ($null -eq $Texte) { return '' }
    $t = $Texte -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"', '&quot;'
    return $t
}


# ===========================================================================
#  0. CONTEXTE D'EXÉCUTION
# ===========================================================================

$estFichier = $false
try {
    if ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $estFichier = $true }
}
catch { }

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Processus 32 bits sur un OS 64 bits : la redirection WOW64 renvoie
# System32\drivers vers SysWOW64 et une partie de HKLM\SOFTWARE vers Wow6432Node.
# Test-Path échouerait alors sur presque tous les pilotes, produisant un parc
# entier de faux « pilotes orphelins » critiques. Cas fréquent quand un agent
# RMM lance PowerShell en 32 bits. On le détecte pour neutraliser ce faux
# positif et signaler que l'audit doit être relancé en 64 bits.
$processus32SurOs64 = ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)

$osInfo = $null
$csInfo = $null
$biosInfo = $null
$build = 0

try { $osInfo   = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { Add-Erreur 'Win32_OperatingSystem' $_.Exception.Message }
try { $csInfo   = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop } catch { Add-Erreur 'Win32_ComputerSystem' $_.Exception.Message }
try { $biosInfo = Get-CimInstance Win32_BIOS            -ErrorAction Stop } catch { Add-Erreur 'Win32_BIOS' $_.Exception.Message }

$osCaption = 'Inconnu'
$osVersion = 'Inconnu'
$dernierDemarrage = 'Inconnu'
if ($osInfo) {
    $osCaption = $osInfo.Caption
    $osVersion = $osInfo.Version
    $build = [int] $osInfo.BuildNumber
    try { $dernierDemarrage = $osInfo.LastBootUpTime.ToString('yyyy-MM-dd HH:mm') } catch { }
}

$domaine = 'Inconnu'
$modele  = 'Inconnu'
$typeMachine = 'Inconnu'
if ($csInfo) {
    $domaine = $csInfo.Domain
    $modele  = ($csInfo.Manufacturer + ' ' + $csInfo.Model).Trim()
    $marqueursVm = 'VMware|Virtual|VirtualBox|KVM|QEMU|Xen|Hyper-V|Parallels|Amazon EC2|Google'
    if ($modele -match $marqueursVm) { $typeMachine = 'Virtuelle' } else { $typeMachine = 'Physique' }
}

$numeroSerie = 'Inconnu'
if ($biosInfo -and $biosInfo.SerialNumber) { $numeroSerie = $biosInfo.SerialNumber.Trim() }

$osSupporte = ($build -ge 10240)

$contexte = New-Object PSObject
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Machine        -Value $env:COMPUTERNAME
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Domaine        -Value $domaine
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Modele         -Value $modele
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Type           -Value $typeMachine
Add-Member -InputObject $contexte -MemberType NoteProperty -Name NumeroSerie    -Value $numeroSerie
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Systeme        -Value $osCaption
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Version        -Value $osVersion
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Build          -Value $build
Add-Member -InputObject $contexte -MemberType NoteProperty -Name DernierDemarrage -Value $dernierDemarrage
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Utilisateur    -Value $identity.Name
Add-Member -InputObject $contexte -MemberType NoteProperty -Name SessionElevee  -Value $isAdmin
Add-Member -InputObject $contexte -MemberType NoteProperty -Name Processus32SurOs64 -Value $processus32SurOs64
Add-Member -InputObject $contexte -MemberType NoteProperty -Name PowerShell     -Value $PSVersionTable.PSVersion.ToString()
Add-Member -InputObject $contexte -MemberType NoteProperty -Name DateAudit      -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
Add-Member -InputObject $contexte -MemberType NoteProperty -Name VersionScript  -Value $VERSION_SCRIPT

# ---------------------------------------------------------------------------
#  Résolution du dossier de livrables
#  Aucune écriture n'est tentée dans un répertoire système. Le premier
#  emplacement réellement accessible en écriture est retenu, après un test
#  d'écriture effectif et non une simple vérification d'existence.
# ---------------------------------------------------------------------------
$ExportPath      = ''
$HtmlReportPath  = ''
$dossierRetenu   = ''
$erreurDossier   = ''

$candidats = @()
if ($DossierRapports -ne '') { $candidats += $DossierRapports }
try { $candidats += (Join-Path ([Environment]::GetFolderPath('Desktop')) 'AGILLY-Audits') } catch { }
try { $candidats += (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'AGILLY-Audits') } catch { }
if ($env:TEMP) { $candidats += (Join-Path $env:TEMP 'AGILLY-Audits') }
if ($env:PUBLIC) { $candidats += (Join-Path $env:PUBLIC 'AGILLY-Audits') }

foreach ($cand in $candidats) {
    if ([string]::IsNullOrWhiteSpace($cand)) { continue }
    # Un chemin de profil non résolu se réduit parfois au seul nom du dossier
    if ($cand -eq 'AGILLY-Audits') { continue }
    try {
        if (-not (Test-Path -LiteralPath $cand)) {
            $null = New-Item -Path $cand -ItemType Directory -Force -ErrorAction Stop
        }
        $jeton = Join-Path $cand ('.ecriture_' + [guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::WriteAllText($jeton, 'test')
        Remove-Item -LiteralPath $jeton -Force -ErrorAction SilentlyContinue
        $dossierRetenu = $cand
        break
    }
    catch {
        $erreurDossier = $_.Exception.Message
    }
}

$horodatage = (Get-Date).ToString('yyyyMMdd-HHmmss')
$baseNom = 'AGILLY_Audit-Socle_' + $env:COMPUTERNAME + '_' + $horodatage
if ($dossierRetenu -ne '') {
    if ($GenererHtml) { $HtmlReportPath = Join-Path $dossierRetenu ($baseNom + '.html') }
    if ($GenererCsv)  { $ExportPath     = Join-Path $dossierRetenu ($baseNom + '.csv') }
}

Write-Host ''
Write-Host '===========================================================' -ForegroundColor DarkYellow
Write-Host '  AGILLY Cyberdéfense' -ForegroundColor Yellow
Write-Host '  Audit du socle Windows face aux vecteurs d''évasion EDR' -ForegroundColor Yellow
Write-Host ('  Version ' + $VERSION_SCRIPT + ' - LECTURE SEULE, aucun appel réseau') -ForegroundColor DarkGray
Write-Host '===========================================================' -ForegroundColor DarkYellow
Write-Host ''
Write-Host 'Portée : les conditions préalables exploitées par les techniques d''évasion.' -ForegroundColor DarkGray
Write-Host 'Ne démontre pas qu''un agent résisterait à une tentative ciblée.' -ForegroundColor DarkGray
Write-Host 'Constat valide sous hypothèse d''un système d''exploitation non compromis.' -ForegroundColor DarkGray
Write-Host ''

if ($dossierRetenu -ne '') {
    Write-Host ('Livrables : ' + $dossierRetenu) -ForegroundColor Cyan
    Write-Host ''
}
elseif ($GenererHtml -or $GenererCsv) {
    Write-Warning 'Aucun dossier accessible en écriture : les livrables ne seront pas générés.'
    if ($erreurDossier -ne '') { Write-Warning ('Dernière erreur : ' + $erreurDossier) }
    Write-Warning 'Renseigner la variable $DossierRapports avec un chemin accessible.'
    Write-Host ''
}

if (-not $isAdmin) {
    Write-Warning 'Session NON élevée : plusieurs contrôles retourneront INDÉTERMINÉ.'
    Write-Warning 'Relancez PowerShell via "Exécuter en tant qu''administrateur".'
    Write-Host ''
}

if ($processus32SurOs64) {
    Write-Warning 'Processus PowerShell 32 bits sur un OS 64 bits (redirection WOW64).'
    Write-Warning 'L''inventaire des pilotes noyau est faussé et sera neutralisé.'
    Write-Warning 'Relancez en 64 bits : %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe'
    Write-Host ''
}

if (-not $osSupporte) {
    Write-Warning ('Build ' + $build + ' antérieur à Windows 10 / Server 2016.')
    Write-Warning 'Plusieurs contrôles ne sont pas disponibles sur cette version.'
    Write-Host ''
}


# ===========================================================================
#  AXE 1, SOCLE FIRMWARE ET INTÉGRITÉ NOYAU
# ===========================================================================

Write-Host '[1/7] Socle firmware et intégrité noyau...' -ForegroundColor DarkCyan

# --- Secure Boot ---
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sb) {
        Add-Finding 'Socle firmware' 'Secure Boot' $ST_OK $CR_CRIT 'Secure Boot actif (firmware UEFI).' 'Aucune action.'
    }
    else {
        Add-Finding 'Socle firmware' 'Secure Boot' $ST_KO $CR_CRIT 'Firmware UEFI présent mais Secure Boot désactivé.' 'Activer Secure Boot : il renforce la chaîne de confiance du démarrage et constitue le socle recommandé de VBS/HVCI et de l''intégrité de signature des pilotes.'
    }
}
catch {
    if (-not $isAdmin) {
        Add-Finding 'Socle firmware' 'Secure Boot' $ST_UNK $CR_CRIT 'Non évaluable sans élévation.' 'Relancer en session administrateur.'
    }
    else {
        Add-Finding 'Socle firmware' 'Secure Boot' $ST_KO $CR_CRIT ('Secure Boot indisponible (firmware non UEFI ou hérité). Détail : ' + $_.Exception.Message) 'Migrer le firmware en UEFI puis activer Secure Boot.'
    }
}

# --- Options de démarrage du noyau (équivalent bcdedit, sans parsing) ---
# testsigning / nointegritychecks désactivent l'intégrité de signature des
# pilotes : le BYOVD devient trivial. kerneldebug autorise l'attachement d'un
# débogueur noyau. Ces options sont normalement verrouillées par Secure Boot,
# mais si celui-ci est absent ou désactivé, elles peuvent l'être. On lit les
# options EFFECTIVES du démarrage en cours dans le registre plutôt que de
# parser une sortie bcdedit localisée.
$sso = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SystemStartOptions'
if ($sso.Error) {
    Add-Finding 'Socle firmware' 'Options de démarrage du noyau' $ST_UNK $CR_CRIT ('Lecture de SystemStartOptions impossible. Détail : ' + $sso.Error) 'Relancer en session administrateur.'
}
elseif (-not $sso.Found) {
    Add-Finding 'Socle firmware' 'Options de démarrage du noyau' $ST_PRES $CR_CRIT 'Aucune option de démarrage particulière déclarée : configuration par défaut présumée.' 'Aucune action ; l''absence de la valeur correspond au comportement standard.'
}
else {
    $optRaw = [string] $sso.Value
    $opt = $optRaw.ToUpper()
    $dangers = @()
    if ($opt -match 'TESTSIGNING')        { $dangers += 'TESTSIGNING (intégrité de signature des pilotes désactivée)' }
    if ($opt -match 'NOINTEGRITYCHECKS')   { $dangers += 'NOINTEGRITYCHECKS (contrôles d''intégrité désactivés)' }
    if ($opt -match 'DISABLE_INTEGRITY_CHECKS') { $dangers += 'DISABLE_INTEGRITY_CHECKS' }
    if ($opt -match 'DEBUG|KERNEL_DEBUG')  { $dangers += 'DEBUG (débogueur noyau autorisé)' }
    if ($dangers.Count -gt 0) {
        Add-Finding 'Socle firmware' 'Options de démarrage du noyau' $ST_KO $CR_CRIT ('Option(s) affaiblissant le noyau active(s) : ' + ($dangers -join ' ; ') + '. Options brutes : ' + $optRaw) 'Retirer ces options (bcdedit /deletevalue ...) et activer/verrouiller Secure Boot, qui empêche leur réactivation. Une machine dans cet état est ouverte au BYOVD quel que soit le reste du durcissement.'
    }
    else {
        Add-Finding 'Socle firmware' 'Options de démarrage du noyau' $ST_OK $CR_CRIT ('Aucune option affaiblissant l''intégrité du noyau. Options actives : ' + $optRaw) 'Aucune action.'
    }
}

# --- DeviceGuard : VBS / HVCI / Credential Guard ---
$dg = $null
$dgErr = $null
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
}
catch {
    $dgErr = $_.Exception.Message
    Add-Erreur 'Win32_DeviceGuard' $dgErr
}

$hvciRunning = $false

if ($null -eq $dg) {
    $d = 'Classe Win32_DeviceGuard inaccessible. Détail : ' + $dgErr
    $r = 'Vérifier les droits et la disponibilité du fournisseur WMI DeviceGuard.'
    Add-Finding 'Intégrité noyau' 'Sécurité basée sur la virtualisation (VBS)' $ST_UNK $CR_ELEV $d $r
    Add-Finding 'Intégrité noyau' 'Intégrité du code (HVCI)' $ST_UNK $CR_CRIT $d $r
    Add-Finding 'Intégrité noyau' 'Credential Guard' $ST_UNK $CR_ELEV $d $r
    Add-Finding 'Intégrité noyau' 'Protection DMA du noyau' $ST_UNK $CR_MOY $d $r
    Add-Finding 'Anti-BYOVD' 'Politique d''intégrité du code (WDAC / App Control)' $ST_UNK $CR_ELEV $d $r
}
else {
    $vbs = $dg.VirtualizationBasedSecurityStatus
    if ($vbs -eq 2) {
        Add-Finding 'Intégrité noyau' 'Sécurité basée sur la virtualisation (VBS)' $ST_OK $CR_ELEV 'VBS active et en cours d''exécution.' 'Aucune action.'
    }
    elseif ($vbs -eq 1) {
        Add-Finding 'Intégrité noyau' 'Sécurité basée sur la virtualisation (VBS)' $ST_KO $CR_ELEV 'VBS configurée mais non démarrée.' 'Vérifier le support matériel (virtualisation, IOMMU) puis redémarrer.'
    }
    else {
        Add-Finding 'Intégrité noyau' 'Sécurité basée sur la virtualisation (VBS)' $ST_KO $CR_ELEV ('VBS inactive (code ' + $vbs + ').') 'Activer VBS après audit de compatibilité des pilotes tiers.'
    }

    $running = @($dg.SecurityServicesRunning)
    $configured = @($dg.SecurityServicesConfigured)

    if ($running -contains 2) {
        $hvciRunning = $true
        Add-Finding 'Intégrité noyau' 'Intégrité du code (HVCI)' $ST_OK $CR_CRIT 'HVCI / intégrité de la mémoire active.' 'Rappel : HVCI n''empêche pas les manipulations de structures noyau (DKOM) par un pilote signé vulnérable.'
    }
    elseif ($configured -contains 2) {
        Add-Finding 'Intégrité noyau' 'Intégrité du code (HVCI)' $ST_KO $CR_CRIT 'HVCI configuré mais non démarré : incompatibilité de pilote probable.' 'Consulter le journal CodeIntegrity/Operational pour identifier le pilote bloquant.'
    }
    else {
        Add-Finding 'Intégrité noyau' 'Intégrité du code (HVCI)' $ST_KO $CR_CRIT 'HVCI inactif.' 'Déployer en mode audit, traiter les incompatibilités, puis forcer.'
    }

    if ($running -contains 1) {
        Add-Finding 'Intégrité noyau' 'Credential Guard' $ST_OK $CR_ELEV 'Credential Guard actif.' 'Aucune action.'
    }
    else {
        Add-Finding 'Intégrité noyau' 'Credential Guard' $ST_KO $CR_ELEV 'Credential Guard inactif.' 'Activer conjointement à la protection LSA pour limiter le vol de secrets d''authentification.'
    }

    # --- Protection DMA du noyau ---
    # La valeur 3 désigne la protection DMA, dans AvailableSecurityProperties
    # pour la compatibilité matérielle et dans RequiredSecurityProperties
    # pour l'exigence portée par la configuration VBS.
    $dmaDispo = @($dg.AvailableSecurityProperties) -contains 3
    $dmaExige = @($dg.RequiredSecurityProperties) -contains 3
    $vbsActif = ($dg.VirtualizationBasedSecurityStatus -eq 2)

    if (-not $dmaDispo) {
        Add-Finding 'Intégrité noyau' 'Protection DMA du noyau' $ST_NA $CR_MOY 'Le matériel ne déclare pas la protection DMA parmi ses capacités.' 'Sur un poste nomade, privilégier au renouvellement une plateforme supportant la protection DMA ; à défaut, désactiver les ports Thunderbolt et DMA externes dans le firmware.'
    }
    elseif ($dmaExige -and $vbsActif) {
        Add-Finding 'Intégrité noyau' 'Protection DMA du noyau' $ST_OK $CR_MOY 'Protection DMA exigée par la configuration VBS, sur un matériel compatible, avec VBS en exécution.' 'Aucune action.'
    }
    elseif ($dmaExige) {
        Add-Finding 'Intégrité noyau' 'Protection DMA du noyau' $ST_CONF $CR_MOY 'Protection DMA exigée par la configuration, mais VBS n''est pas en exécution : l''exigence n''est pas appliquée.' 'Traiter d''abord l''activation de VBS ; la protection DMA suivra.'
    }
    else {
        Add-Finding 'Intégrité noyau' 'Protection DMA du noyau' $ST_KO $CR_MOY 'Matériel compatible, mais la protection DMA n''est pas exigée par la configuration VBS.' 'Ajouter la protection DMA aux propriétés de sécurité requises. Elle bloque les accès mémoire directs par périphérique externe, vecteur d''accès au noyau sans exécution de code sur le système. Contrôle pertinent surtout sur les postes nomades.'
    }

    # --- Politique d'intégrité du code (WDAC / App Control) ---
    # 0 = désactivée, 1 = mode audit, 2 = appliquée.
    # Le statut « appliquée » ne dit RIEN de ce que la politique couvre : une
    # politique en mode utilisateur seul n'oppose aucune barrière au BYOVD. Sur
    # Windows récent, la liste de blocage Microsoft est elle-même livrée comme
    # politique WDAC : un statut = 2 peut ne refléter qu'elle. On énumère donc
    # les politiques actives (CiTool, Win11 22H2+/Server 2022+) pour distinguer
    # une politique d'organisation d'une base Microsoft par défaut.
    $ciStatus = $dg.CodeIntegrityPolicyEnforcementStatus
    $ciPolitiques = @()
    $ciPolitiquesLisible = $false
    $ciOrgPresente = $false
    if (Get-Command CiTool -ErrorAction SilentlyContinue) {
        try {
            # Deux pièges de CiTool corrigés ici :
            # 1) le flag JSON est « -json » (un seul tiret) ; « --json » n'est
            #    pas reconnu et fait retomber l'outil en mode texte interactif.
            # 2) en mode texte, CiTool attend une frappe clavier avant de rendre
            #    la main (comportement documenté). On alimente donc stdin d'une
            #    ligne vide pour qu'aucune exécution ne puisse bloquer l'audit.
            $ciJson = '' | & CiTool -lp -json 2>$null | Out-String
            if ($ciJson) {
                $ciObj = $ciJson | ConvertFrom-Json
                $ciListe = $ciObj.Policies
                if ($null -eq $ciListe) { $ciListe = $ciObj }
                foreach ($p in @($ciListe)) {
                    # IsEnforced est rendu comme chaîne « True »/« False » : une
                    # comparaison de vérité brute prendrait « False » pour vrai.
                    $enf = ($p.IsEnforced -eq $true) -or ("$($p.IsEnforced)" -eq 'True')
                    if ($enf) {
                        $nom = $p.FriendlyName
                        if (-not $nom) { $nom = $p.PolicyID }
                        if ($nom) {
                            $ciPolitiques += $nom
                            if ($nom -notmatch 'Microsoft|Windows Driver|Recommended|Blocklist|Blocking|Vulnerable') { $ciOrgPresente = $true }
                        }
                    }
                }
                $ciPolitiquesLisible = $true
            }
        }
        catch { }
    }
    $ciDetailPol = ''
    if ($ciPolitiques.Count -gt 0) { $ciDetailPol = ' Politiques actives : ' + (($ciPolitiques | Select-Object -Unique) -join ', ') + '.' }

    if ($ciStatus -eq 2 -and $ciOrgPresente) {
        Add-Finding 'Anti-BYOVD' 'Politique d''intégrité du code (WDAC / App Control)' $ST_OK $CR_ELEV ('Politique d''intégrité du code d''organisation appliquée en mode blocage.' + $ciDetailPol) 'Confirmer que la politique inclut bien une règle sur les pilotes (signataire ou version), et non uniquement des applications en mode utilisateur.'
    }
    elseif ($ciStatus -eq 2) {
        $motifPol = 'Impossible d''énumérer les politiques actives (CiTool indisponible ou illisible) : la couverture des pilotes ne peut être confirmée.'
        if ($ciPolitiquesLisible) { $motifPol = 'Seule(s) une ou des politique(s) Microsoft par défaut détectée(s), sans politique d''organisation : la couverture se limite à la liste de blocage Microsoft.' }
        Add-Finding 'Anti-BYOVD' 'Politique d''intégrité du code (WDAC / App Control)' $ST_PRES $CR_ELEV ('Une politique d''intégrité du code est appliquée, mais son périmètre n''est pas établi. ' + $motifPol + $ciDetailPol) 'Ne pas conclure à une protection anti-BYOVD sur ce seul statut. Déployer une politique WDAC d''organisation autorisant les pilotes par signataire ; la base Microsoft ne rejette qu''un échantillon connu.'
    }
    elseif ($ciStatus -eq 1) {
        Add-Finding 'Anti-BYOVD' 'Politique d''intégrité du code (WDAC / App Control)' $ST_CONF $CR_ELEV 'Politique d''intégrité du code en mode audit : les chargements non conformes sont journalisés mais autorisés.' 'Exploiter le journal CodeIntegrity/Operational pour mesurer l''impact, puis basculer en mode appliqué.'
    }
    else {
        Add-Finding 'Anti-BYOVD' 'Politique d''intégrité du code (WDAC / App Control)' $ST_KO $CR_ELEV 'Aucune politique d''intégrité du code appliquée.' 'C''est l''une des principales contre-mesures préventives au BYOVD lorsqu''elle couvre effectivement les pilotes : elle les autorise par signataire ou par version, là où la liste de blocage Microsoft ne rejette qu''un échantillon connu et où la règle ASR n''empêche que l''écriture sur disque. Son efficacité dépend du contenu et du mode d''application de la politique. À cibler en priorité sur les serveurs et les postes sensibles.'
    }
}

# --- Protection LSA ---
# La valeur de registre ne prend effet qu'au démarrage suivant. Lire la clé
# seule produirait un faux CONFORME sur une machine fraîchement configurée
# et non redémarrée, état qu'un attaquant peut d'ailleurs fabriquer.
# Windows journalise l'activation réelle : Wininit, événement 12 dans le
# journal Système, à chaque démarrage où LSASS est lancé en processus protégé.
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ppl     = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
$pplBoot = Get-RegValue -Path $lsaPath -Name 'RunAsPPLBoot'

$pplConfigure = ($ppl.Found -and (@(1, 2) -contains [int] $ppl.Value)) -or ($pplBoot.Found -and (@(1, 2) -contains [int] $pplBoot.Value))
$pplActifPreuve = $false
$pplPreuveLisible = $false

# Sur un serveur à longue disponibilité, l'événement 12 du dernier démarrage
# a pu sortir du journal Système par rotation. Conclure « non actif » sur son
# absence serait alors un faux négatif. On détecte le cas en comparant le plus
# ancien événement encore présent dans le journal à l'heure de démarrage : si
# le journal ne remonte pas jusqu'au boot, l'absence de 12 n'est pas probante.
$journalRemonteAuBoot = $true
if ($osInfo) {
    try {
        $plusAncien = Get-WinEvent -LogName 'System' -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($plusAncien -and $plusAncien.TimeCreated -gt $osInfo.LastBootUpTime) {
            $journalRemonteAuBoot = $false
        }
    }
    catch { $journalRemonteAuBoot = $false }
}

if ($osInfo) {
    try {
        $evPpl = Get-Evenements -Journal 'System' -Ids @(12) -Depuis $osInfo.LastBootUpTime -Fournisseur 'Microsoft-Windows-Wininit' -Max 20
        if ($null -eq $evPpl.Erreur) {
            $pplPreuveLisible = $true
            foreach ($e in $evPpl.Evenements) {
                if ($e.Message -match 'protected process|processus prot') { $pplActifPreuve = $true }
            }
        }
    }
    catch { }
}

if ($ppl.Error) {
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_UNK $CR_ELEV ('Clé de registre inaccessible. Détail : ' + $ppl.Error) 'Relancer en session administrateur.'
}
elseif ($pplActifPreuve) {
    # Preuve d'activation présente. Vaut aussi sur les builds récents où la
    # protection est active par défaut sans valeur de registre : l'événement
    # 12 tranche ce que le registre seul laisserait en INDÉTERMINÉ.
    $niveau = 'sans verrou UEFI : la configuration reste modifiable par un administrateur local'
    if ($ppl.Found -and [int] $ppl.Value -eq 1) {
        $niveau = 'niveau 1, avec verrou UEFI : protection renforcée contre la modification de la configuration par un administrateur local'
    }
    elseif ($ppl.Found -and [int] $ppl.Value -eq 2) {
        $niveau = 'niveau 2, sans verrou UEFI : la configuration reste modifiable par un administrateur local'
    }
    else {
        $niveau = 'active par défaut sur ce build, sans valeur de registre explicite'
    }
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_OK $CR_ELEV ('LSASS exécuté en processus protégé, ' + $niveau + '. Activation confirmée par le journal de démarrage.') 'La preuve d''activation est l''événement Wininit 12, pas la valeur de registre. Selon la documentation Microsoft, RunAsPPL=1 correspond au verrou UEFI et 2 à son absence ; à défaut de verrou, la configuration reste modifiable par un administrateur local. RunAsPPL reste par ailleurs contournable par un pilote vulnérable signé : à coupler avec HVCI et Credential Guard.'
}
elseif ($pplConfigure -and $pplPreuveLisible -and $journalRemonteAuBoot) {
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_CONF $CR_ELEV 'Valeur de registre positionnée, mais aucun événement Wininit 12 depuis le dernier démarrage alors que le journal remonte jusqu''à celui-ci : la protection n''est pas active en mémoire.' 'Redémarrer la machine pour appliquer la configuration, puis relancer l''audit. Tant que le redémarrage n''a pas eu lieu, LSASS n''est pas protégé.'
}
elseif ($pplConfigure) {
    $motif = 'Le journal de démarrage n''a pas pu être lu'
    if ($pplPreuveLisible -and -not $journalRemonteAuBoot) { $motif = 'Le journal Système ne remonte pas jusqu''au dernier démarrage (rotation) : l''absence de l''événement 12 n''est pas probante' }
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_PRES $CR_ELEV ('Valeur de registre positionnée. ' + $motif + ' : l''activation en mémoire n''est pas confirmée.') 'Vérifier la présence de l''événement Wininit 12 dans le journal Système après le dernier démarrage, ou augmenter la taille du journal Système sur les serveurs à longue disponibilité.'
}
elseif ($build -ge 22621) {
    $noteJournal = ''
    if (-not $journalRemonteAuBoot) { $noteJournal = ' Le journal ne remonte pas jusqu''au démarrage : une activation par défaut ne peut être ni confirmée ni exclue.' }
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_UNK $CR_ELEV ('Aucune valeur présente et aucun événement Wininit 12 exploitable. Sur le build ' + $build + ', la protection peut être active par défaut sans valeur de registre.' + $noteJournal) 'Forcer RunAsPPL explicitement pour rendre l''état auditable, puis confirmer par l''événement Wininit 12.'
}
else {
    Add-Finding 'Intégrité noyau' 'Protection LSA (RunAsPPL)' $ST_KO $CR_ELEV 'Protection LSA non activée.' 'Activer en mode audit, traiter les incompatibilités (SSO, DLP, cartes à puce), puis forcer.'
}


# ===========================================================================
#  AXE 2, ANTI-BYOVD
# ===========================================================================

Write-Host '[2/7] Contrôles anti-BYOVD...' -ForegroundColor DarkCyan

$blPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$bl = Get-RegValue -Path $blPath -Name 'VulnerableDriverBlocklistEnable'

if ($bl.Error) {
    Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_UNK $CR_CRIT ('Clé de registre inaccessible. Détail : ' + $bl.Error) 'Relancer en session administrateur.'
}
elseif ($bl.Found -and [int] $bl.Value -eq 1) {
    # Aucun événement Windows ne prouve l'activation en mémoire de la
    # blocklist. HVCI actif est le seul indice corroborant disponible.
    if ($hvciRunning) {
        Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_OK $CR_CRIT 'Liste de blocage forcée explicitement (valeur = 1), avec HVCI actif comme indice d''application effective.' 'Compléter par une politique App Control / WDAC sur les pilotes pour les actifs sensibles : la liste Microsoft ne couvre qu''une fraction des pilotes vulnérables recensés.'
    }
    else {
        Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_PRES $CR_CRIT 'Liste de blocage forcée explicitement (valeur = 1). Cette valeur ne prend effet qu''au démarrage suivant et aucun événement Windows n''en atteste l''application : l''audit ne peut pas confirmer l''état en mémoire.' 'Vérifier le journal CodeIntegrity/Operational après redémarrage. Compléter par une politique App Control / WDAC sur les pilotes pour les actifs sensibles.'
    }
}
elseif ($bl.Found -and [int] $bl.Value -eq 0) {
    Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_KO $CR_CRIT 'Liste de blocage DÉSACTIVÉE explicitement (valeur = 0).' 'Désactivation volontaire : investiguer en priorité l''origine de ce paramétrage.'
}
elseif ($build -ge 22621 -or $hvciRunning) {
    $ctx = 'build ' + $build
    if ($hvciRunning) { $ctx = 'HVCI actif' }
    Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_PRES $CR_CRIT ('Valeur absente. La protection est activée par défaut dans ce contexte (' + $ctx + '), mais l''état n''est pas mesuré directement.') 'Forcer explicitement la valeur à 1 pour rendre l''état auditable, puis vérifier via le journal CodeIntegrity/Operational.'
}
else {
    Add-Finding 'Anti-BYOVD' 'Liste de blocage des pilotes vulnérables' $ST_KO $CR_CRIT ('Valeur absente et build ' + $build + ' antérieur à l''activation par défaut.') 'Déployer la liste de blocage et évaluer une politique WDAC alimentée par LOLDrivers.'
}


# ===========================================================================
#  AXE 3, AGENTS DE SÉCURITÉ PRÉSENTS ET INTÉGRITÉ
# ===========================================================================

Write-Host '[3/7] Détection des agents de sécurité...' -ForegroundColor DarkCyan

# Détection par mot-clé éditeur sur le nom affiché et le chemin binaire.
# Choix assumé : la correspondance par nom d'éditeur est plus robuste dans
# le temps qu'une table de noms de services exacts, qui change à chaque
# version majeure d'agent.
# Détection par mot-clé éditeur sur le nom de service, le nom affiché et
# le chemin binaire. Choix assumé : la correspondance par nom d'éditeur est
# plus robuste dans le temps qu'une table de noms de services exacts, qui
# change à chaque version majeure d'agent.
# Deux catégories distinctes : un collecteur de télémétrie n'est pas un
# agent de protection et ne doit pas laisser croire à une couverture EDR.
$editeurs = @()
$editeurs += , @('Check Point / Harmony', 'Check ?Point|CPDA|Endpoint Security VPN|Harmony')
$editeurs += , @('CrowdStrike Falcon', 'CrowdStrike|CSFalcon|CSAgent')
$editeurs += , @('SentinelOne', 'SentinelOne|Sentinel Agent')
$editeurs += , @('Palo Alto Cortex XDR', 'Cortex XDR|Cyvera|Traps|Palo Alto')
$editeurs += , @('Trend Micro', 'Trend Micro|Apex One|OfficeScan|ds_agent')
$editeurs += , @('Microsoft Defender', 'WinDefend|MsMpEng|MsSense|Defender Antivirus|Defender for Endpoint|Defender Advanced')
$editeurs += , @('Sophos', 'Sophos')
$editeurs += , @('Kaspersky', 'Kaspersky')
$editeurs += , @('ESET', 'ESET')
$editeurs += , @('Bitdefender', 'Bitdefender')
$editeurs += , @('Trellix / McAfee', 'Trellix|McAfee')
$editeurs += , @('Symantec / Broadcom', 'Symantec|Broadcom')
$editeurs += , @('VMware Carbon Black', 'Carbon Black|CbDefense')
$editeurs += , @('Cylance', 'Cylance')
$editeurs += , @('Guardz', 'Guardz')

# Collecteurs de télémétrie : utiles à la supervision, sans capacité de
# protection. Comptabilisés séparément.
$collecteurs = @()
$collecteurs += , @('Sysmon', '^Sysmon')
$collecteurs += , @('Wazuh / OSSEC', 'Wazuh|OSSEC')
$collecteurs += , @('Datadog', 'Datadog')
$collecteurs += , @('Elastic Agent', 'Elastic Agent|winlogbeat')

# Services à exclure : composants Windows dont le nom affiché contient
# « Defender » sans être un agent de protection. Sur un système
# francophone, « Pare-feu Windows Defender » (MpsSvc) serait sinon compté
# comme un service de sécurité, et son type de démarrage produirait un
# constat sans rapport avec l'EDR.
$exclusionsServices = '^MpsSvc$|^mpsdrv$|^BFE$|^SecurityHealthService$|^wscsvc$'

$services = @()
try {
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
}
catch {
    Add-Erreur 'Win32_Service' $_.Exception.Message
}

$agentsDetectes = @()
$servicesSecurite = @()

foreach ($e in $editeurs) {
    $nomEditeur = $e[0]
    $motif = $e[1]
    $corresp = @($services | Where-Object {
        ($_.DisplayName -and $_.DisplayName -match $motif) -or
        ($_.Name -and $_.Name -match $motif) -or
        ($_.PathName -and $_.PathName -match $motif)
    })
    $corresp = @($corresp | Where-Object { $_.Name -notmatch $exclusionsServices })
    if ($corresp.Count -gt 0) {
        $agentsDetectes += $nomEditeur
        foreach ($s in $corresp) { $servicesSecurite += $s }
    }
}

$collecteursDetectes = @()
foreach ($c in $collecteurs) {
    $motifC = $c[1]
    $trouve = @($services | Where-Object {
        ($_.Name -and $_.Name -match $motifC) -or
        ($_.DisplayName -and $_.DisplayName -match $motifC)
    })
    if ($trouve.Count -gt 0) { $collecteursDetectes += $c[0] }
}

$agentsDetectes = @($agentsDetectes | Select-Object -Unique)
$collecteursDetectes = @($collecteursDetectes | Select-Object -Unique)

# Defender Antivirus est présent sur tout Windows : sa détection ne dit rien du
# dispositif en place. Ce qui change la lecture de la moitié des contrôles, c'est
# la présence d'un agent TIERS en protection primaire, auquel cas les services,
# l'anti-sabotage et les signatures de Defender deviennent hors sujet, et c'est
# la console de l'éditeur qui fait foi.
$agentsTiers = @($agentsDetectes | Where-Object { $_ -ne 'Microsoft Defender' })
$agentTiersPrimaire = ($agentsTiers.Count -gt 0)
$nomAgentTiers = 'un agent tiers'
if ($agentTiersPrimaire) { $nomAgentTiers = ($agentsTiers -join ', ') }

# Services propres à la pile Microsoft. Arrêtés sur une machine protégée par un
# agent tiers, c'est le comportement attendu, pas un incident.
$servicesPileMicrosoft = @('WinDefend', 'WdNisSvc', 'Sense', 'MsSense', 'SecurityHealthService', 'MsSecFlt', 'wscsvc')

# Machine hors domaine : LAPS et la collecte WEF supposent une infrastructure
# d'annuaire. Les évaluer sur un poste isolé produit un écart sans objet.
$horsDomaine = ($domaine -eq '' -or $domaine -eq 'WORKGROUP' -or $domaine -eq 'Inconnu' -or $domaine -eq $env:COMPUTERNAME)
$servicesSecurite = @($servicesSecurite | Sort-Object Name -Unique)

if ($services.Count -eq 0) {
    Add-Finding 'Intégrité de l''agent' 'Agents de sécurité détectés' $ST_UNK $CR_CRIT 'Énumération des services impossible.' 'Relancer en session administrateur.'
}
elseif ($agentsDetectes.Count -eq 0) {
    Add-Finding 'Intégrité de l''agent' 'Agents de sécurité détectés' $ST_KO $CR_CRIT 'Aucun agent de sécurité reconnu sur cette machine.' 'Vérifier la couverture du parc : une machine sans agent est un angle mort de supervision.'
}
else {
    $detAgents = 'Éditeurs identifiés : ' + ($agentsDetectes -join ', ') + '. Services associés : ' + $servicesSecurite.Count + '.'
    if ($collecteursDetectes.Count -gt 0) {
        $detAgents += ' Collecteurs de télémétrie présents, sans capacité de protection : ' + ($collecteursDetectes -join ', ') + '.'
    }
    # Inventaire détaillé pour rendre l'heuristique de détection vérifiable par
    # le lecteur du rapport, plutôt qu'un simple nom d'éditeur.
    $detAgents += ' Détail : ' + (($servicesSecurite | ForEach-Object {
        $ch = [string] $_.PathName
        if ($ch.Length -gt 80) { $ch = $ch.Substring(0, 77) + '...' }
        $_.Name + ' [' + $_.DisplayName + '], ' + $_.State + ' / ' + $_.StartMode + ' / ' + $ch
    }) -join ' | ') + '.'
    Add-Finding 'Intégrité de l''agent' 'Agents de sécurité détectés' $ST_INFO $CR_INFO $detAgents 'Vérifier que l''agent identifié correspond bien à la solution contractuelle du client, et que les chemins listés pointent vers les binaires attendus de l''éditeur.'
}

# --- État des services de sécurité ---
if ($servicesSecurite.Count -gt 0) {
    # Un service arrêté, ou désactivé (Disabled), est un vrai écart critique.
    # En revanche « Manual + Running » n'en est pas un : plusieurs agents
    # utilisent légitimement un démarrage déclenché (trigger-start) plutôt
    # qu'Automatic. Le mode Manual n'est une anomalie que si le service est
    # aussi à l'arrêt.
    $svcEvalues = $servicesSecurite
    $svcMsEcartes = @()
    if ($agentTiersPrimaire) {
        $svcMsEcartes = @($servicesSecurite | Where-Object { $servicesPileMicrosoft -contains $_.Name -and $_.State -ne 'Running' })
        $svcEvalues = @($servicesSecurite | Where-Object { -not ($servicesPileMicrosoft -contains $_.Name -and $_.State -ne 'Running') })
    }
    $arretes    = @($svcEvalues | Where-Object { $_.State -ne 'Running' -and $_.StartMode -ne 'Disabled' })
    $desactives = @($svcEvalues | Where-Object { $_.StartMode -eq 'Disabled' })
    $manuelActifs = @($svcEvalues | Where-Object { $_.StartMode -eq 'Manual' -and $_.State -eq 'Running' })
    $mentionMs = ''
    if ($svcMsEcartes.Count -gt 0) {
        $mentionMs = ' Service(s) de la pile Microsoft à l''arrêt, comportement attendu sous ' + $nomAgentTiers + ' : ' + (($svcMsEcartes | ForEach-Object { $_.Name }) -join ', ') + '.'
    }

    if ($arretes.Count -eq 0 -and $desactives.Count -eq 0) {
        $det = $svcEvalues.Count.ToString() + ' service(s) de l''agent en place évalué(s).' + $mentionMs
        if ($manuelActifs.Count -gt 0) {
            $det += ' Dont ' + $manuelActifs.Count + ' en démarrage manuel/déclenché mais actif(s) : ' + (($manuelActifs | ForEach-Object { $_.Name }) -join ', ') + '.'
            Add-Finding 'Intégrité de l''agent' 'État des services de sécurité' $ST_INFO $CR_INFO $det 'Le démarrage manuel actif est légitime pour certains agents (trigger-start). Confirmer que ce mode est bien celui prévu par l''éditeur, et non le résultat d''une reconfiguration.'
        }
        else {
            Add-Finding 'Intégrité de l''agent' 'État des services de sécurité' $ST_OK $CR_CRIT ($det + ' Tous en démarrage automatique.') 'Aucune action.'
        }
    }
    else {
        $det = ''
        if ($arretes.Count -gt 0)    { $det += 'Arrêté(s) : ' + (($arretes | ForEach-Object { $_.Name }) -join ', ') + '. ' }
        if ($desactives.Count -gt 0) { $det += 'Désactivé(s) : ' + (($desactives | ForEach-Object { $_.Name }) -join ', ') + '.' }
        Add-Finding 'Intégrité de l''agent' 'État des services de sécurité' $ST_KO $CR_CRIT ($det + $mentionMs) 'Un service de sécurité arrêté ou désactivé doit être traité comme un incident, pas comme une anomalie de configuration.'
    }

    # --- Enregistrement en mode sans échec ---
    # On teste Minimal ET Network. L'absence n'est pas une non-conformité
    # ferme : tous les agents ne sont pas conçus pour démarrer en mode sans
    # échec, et l'absence ne prouve pas un contournement. On la signale comme
    # point à vérifier plutôt qu'en KO critique.
    $safeBootOk = @()
    foreach ($s in $servicesSecurite) {
        $cheminMin = 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\' + $s.Name
        $cheminNet = 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\' + $s.Name
        $zones = @()
        if (Test-Path -LiteralPath $cheminMin) { $zones += 'Minimal' }
        if (Test-Path -LiteralPath $cheminNet) { $zones += 'Network' }
        if ($zones.Count -gt 0) { $safeBootOk += ($s.Name + ' (' + ($zones -join '+') + ')') }
    }
    if ($safeBootOk.Count -gt 0) {
        Add-Finding 'Intégrité de l''agent' 'Démarrage en mode sans échec' $ST_OK $CR_ELEV ($safeBootOk.Count.ToString() + ' service(s) de sécurité enregistré(s) pour le mode sans échec : ' + ($safeBootOk -join ', ') + '.') 'Aucune action.'
    }
    else {
        Add-Finding 'Intégrité de l''agent' 'Démarrage en mode sans échec' $ST_PRES $CR_ELEV 'Aucun service de sécurité enregistré sous SafeBoot\Minimal ni SafeBoot\Network.' 'Le démarrage en mode sans échec est un vecteur documenté de contournement d''EDR par les opérateurs de rançongiciel, mais tous les agents ne prennent pas en charge ce mode. Vérifier auprès de l''éditeur si l''agent doit y démarrer ; à défaut, bloquer le démarrage en mode sans échec par la règle ASR dédiée ou par stratégie.'
    }
}

# --- Defender : mode, temps réel, anti-sabotage, signatures, exclusions ---
$mp = $null
$mpErr = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mpErr = $_.Exception.Message }

$defenderActif = $false
$mode = 'Indisponible'
$modeAff = 'indisponible'

if ($null -eq $mp) {
    # Contexte agent tiers : ces contrôles relèvent de la console de l'éditeur,
    # pas d'un échec de lecture de notre fait. L'état « À VÉRIFIER EN CONSOLE »
    # (distinct d'INDÉTERMINÉ) évite qu'un poste sous SentinelOne, CrowdStrike
    # ou Harmony ressorte avec une couverture d'audit artificiellement plus
    # basse qu'un poste équivalent sous Defender.
    $d = 'Module Defender indisponible : protection assurée par un agent tiers. Détail : ' + $mpErr
    Add-Finding 'Intégrité de l''agent' 'Mode d''exécution Defender' $ST_INFO $CR_INFO $d 'Documenter et auditer l''agent tiers en place depuis sa console.'
    Add-Finding 'Intégrité de l''agent' 'Protection temps réel' $ST_CONSOLE $CR_CRIT $d 'Vérifier l''état de la protection temps réel depuis la console de l''éditeur.'
    Add-Finding 'Intégrité de l''agent' 'Protection anti-sabotage' $ST_CONSOLE $CR_CRIT $d 'Vérifier le mécanisme anti-sabotage de l''agent tiers (mot de passe de désinstallation, jeton de maintenance).'
    Add-Finding 'Intégrité de l''agent' 'Fraîcheur des signatures' $ST_CONSOLE $CR_MOY $d 'Vérifier depuis la console de l''éditeur.'
    Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_CONSOLE $CR_ELEV $d 'Extraire et revoir les exclusions depuis la console de l''éditeur.'
}
else {
    if ($mp.PSObject.Properties.Name -contains 'AMRunningMode') { $mode = [string] $mp.AMRunningMode }
    if ($mode -eq 'Normal') { $defenderActif = $true }

    # L'API rend ces valeurs en anglais. Les restituer telles quelles dans un
    # rapport client francophone n'est pas tenable ; la valeur brute est
    # conservée dans $mode pour les comparaisons.
    $modeAff = $mode
    switch ($mode) {
        'Normal'           { $modeAff = 'actif' }
        'Passive'          { $modeAff = 'passif' }
        'Passive Mode'     { $modeAff = 'passif' }
        'SxS Passive Mode' { $modeAff = 'passif, analyse périodique' }
        'EDR Block Mode'   { $modeAff = 'blocage EDR' }
        'Not running'      { $modeAff = 'arrêté' }
        default            { $modeAff = $mode }
    }

    if ($defenderActif) {
        Add-Finding 'Intégrité de l''agent' 'Mode d''exécution Defender' $ST_INFO $CR_INFO 'Defender est l''antivirus actif : les règles ASR sont applicables.' 'Aucune action.'
    }
    else {
        Add-Finding 'Intégrité de l''agent' 'Mode d''exécution Defender' $ST_INFO $CR_INFO ('Defender en mode « ' + $modeAff + ' » : un agent tiers assure la protection primaire.') 'Les règles ASR ne s''appliquent pas dans ce mode. Auditer les contrôles équivalents chez l''éditeur de l''agent primaire.'
    }

    # Temps réel
    $rtp = $null
    if ($mp.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') { $rtp = $mp.RealTimeProtectionEnabled }
    if ($null -eq $rtp) {
        Add-Finding 'Intégrité de l''agent' 'Protection temps réel' $ST_UNK $CR_CRIT 'État non exposé par cette version de Defender.' 'Vérifier depuis le portail de gestion.'
    }
    elseif ($rtp) {
        Add-Finding 'Intégrité de l''agent' 'Protection temps réel' $ST_OK $CR_CRIT 'Protection temps réel active.' 'Aucune action.'
    }
    elseif (-not $defenderActif) {
        Add-Finding 'Intégrité de l''agent' 'Protection temps réel' $ST_NA $CR_CRIT ('Defender en mode « ' + $modeAff + ' » : la protection temps réel est assurée par l''agent tiers.') 'Vérifier l''état temps réel dans la console de l''agent primaire.'
    }
    else {
        Add-Finding 'Intégrité de l''agent' 'Protection temps réel' $ST_KO $CR_CRIT 'Protection temps réel DÉSACTIVÉE alors que Defender est l''antivirus actif.' 'Traiter comme un incident : c''est l''état recherché par un attaquant après compromission.'
    }

    # Anti-sabotage
    $tamper = $null
    if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') { $tamper = $mp.IsTamperProtected }
    if (-not $defenderActif) {
        Add-Finding 'Intégrité de l''agent' 'Protection anti-sabotage' $ST_CONSOLE $CR_CRIT ('Defender n''est pas l''antivirus actif : son anti-sabotage ne protège rien ici. La protection est assurée par ' + $nomAgentTiers + '.') 'Vérifier le mécanisme anti-sabotage de l''agent en place depuis sa console : mot de passe de désinstallation, jeton de maintenance, verrouillage de la politique locale.'
    }
    elseif ($null -eq $tamper) {
        Add-Finding 'Intégrité de l''agent' 'Protection anti-sabotage' $ST_UNK $CR_CRIT 'État non exposé par cette version de Defender.' 'Vérifier depuis le portail de gestion centralisée.'
    }
    elseif ($tamper) {
        Add-Finding 'Intégrité de l''agent' 'Protection anti-sabotage' $ST_OK $CR_CRIT 'Protection anti-sabotage active.' 'Rappel : l''anti-sabotage ne résiste pas à une terminaison initiée depuis le noyau.'
    }
    else {
        Add-Finding 'Intégrité de l''agent' 'Protection anti-sabotage' $ST_KO $CR_CRIT 'Protection anti-sabotage inactive.' 'Activer et verrouiller depuis la console centrale, et non en local.'
    }

    # Signatures
    $age = $null
    if ($mp.PSObject.Properties.Name -contains 'AntivirusSignatureAge') { $age = $mp.AntivirusSignatureAge }
    if (-not $defenderActif) {
        Add-Finding 'Intégrité de l''agent' 'Fraîcheur des signatures' $ST_CONSOLE $CR_MOY ('Defender n''est pas l''antivirus actif : l''âge de ses signatures ne reflète pas la protection réelle, assurée par ' + $nomAgentTiers + '.') 'Vérifier la fraîcheur des bases depuis la console de l''éditeur en place.'
    }
    elseif ($null -eq $age -or [int] $age -ge 65535) {
        # 65535 est la valeur de substitution renvoyée par Defender quand aucune
        # mise à jour n'a jamais été appliquée : la restituer telle quelle ferait
        # état de signatures vieilles de 179 ans dans un rapport client.
        Add-Finding 'Intégrité de l''agent' 'Fraîcheur des signatures' $ST_UNK $CR_MOY 'Âge des signatures non exposé, ou valeur de substitution renvoyée par Defender.' 'Vérifier depuis le portail de gestion.'
    }
    elseif ([int] $age -le 7) {
        Add-Finding 'Intégrité de l''agent' 'Fraîcheur des signatures' $ST_OK $CR_MOY ('Signatures âgées de ' + $age + ' jour(s).') 'Aucune action.'
    }
    else {
        Add-Finding 'Intégrité de l''agent' 'Fraîcheur des signatures' $ST_KO $CR_MOY ('Signatures âgées de ' + $age + ' jour(s).') 'Une machine qui ne met plus à jour ses signatures ne communique probablement plus avec sa console.'
    }

    # Exclusions
    # En session NON élevée, Get-MpPreference retourne pour chaque exclusion la
    # chaîne « N/A: Must be an administrator... » au lieu des vraies valeurs :
    # les compter comme exclusions produirait un faux « X exclusions définies »
    # (et pourrait masquer un vrai KO). On exige l'élévation pour ce contrôle.
    if (-not $isAdmin) {
        Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_UNK $CR_ELEV 'Les exclusions ne sont pas lisibles en session non élevée (Get-MpPreference renvoie une valeur de substitution).' 'Relancer en session administrateur.'
    }
    else {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            # Filtrer la valeur de substitution renvoyée en cas de droits insuffisants.
            $motifNA = '^N/?A\b|Must be an administrator|doit .tre un administrateur'
            $exPath = @($pref.ExclusionPath    | Where-Object { $_ -and $_ -notmatch $motifNA })
            $exProc = @($pref.ExclusionProcess | Where-Object { $_ -and $_ -notmatch $motifNA })
            $exExt  = @($pref.ExclusionExtension | Where-Object { $_ -and $_ -notmatch $motifNA })
            $total = $exPath.Count + $exProc.Count + $exExt.Count

            # Chemins à portée large. Sans ancrage final : une exclusion
            # C:\Users\bob est aussi dangereuse que \Users et doit être prise.
            $motifRisque = '^[A-Za-z]:\\?$|\\Users(\\|$)|\\Temp(\\|$)|\\Windows(\\|$)|\\ProgramData(\\|$)|\\Public(\\|$)|\\AppData(\\|$)|\\Downloads(\\|$)'
            $risquees = @($exPath | Where-Object { $_ -match $motifRisque })

            # Extensions et processus qui neutralisent des vecteurs d'évasion.
            $motifExtRisque = '(?i)\.?(sys|dll|exe|ps1|scr|com)$'
            $extRisque = @($exExt | Where-Object { $_ -match $motifExtRisque })
            $motifProcRisque = '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|psexec|wmic)'
            $procRisque = @($exProc | Where-Object { $_ -match $motifProcRisque })

            $alertes = @()
            if ($risquees.Count -gt 0)  { $alertes += 'chemin(s) large(s) : ' + ($risquees -join ', ') }
            if ($extRisque.Count -gt 0) { $alertes += 'extension(s) sensible(s) : ' + ($extRisque -join ', ') }
            if ($procRisque.Count -gt 0){ $alertes += 'processus d''évasion : ' + ($procRisque -join ', ') }

            if ($total -eq 0) {
                Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_OK $CR_ELEV 'Aucune exclusion définie.' 'Aucune action.'
            }
            elseif ($alertes.Count -gt 0) {
                Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_KO $CR_ELEV ($total.ToString() + ' exclusion(s) dont des entrées à risque, ' + ($alertes -join ' ; ') + '.') 'Une exclusion de racine, de répertoire utilisateur, d''extension exécutable ou d''interpréteur neutralise la protection sur un périmètre entier et sert directement l''évasion. Revoir et justifier chaque entrée ; l''ajout d''exclusions est une technique d''attaque documentée.'
            }
            else {
                Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_INFO $CR_INFO ($total.ToString() + ' exclusion(s) définie(s) : ' + $exPath.Count + ' chemin(s), ' + $exProc.Count + ' processus, ' + $exExt.Count + ' extension(s). Aucune à portée manifestement large.') 'Revoir la justification métier de chaque exclusion et vérifier qu''aucune n''a été ajoutée hors processus de changement.'
            }
        }
        catch {
            if (-not $defenderActif) {
                Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_CONSOLE $CR_ELEV ('Préférences Defender non lisibles, le service n''étant pas actif : la protection est assurée par ' + $nomAgentTiers + '. Détail : ' + $_.Exception.Message) 'Extraire et revoir les exclusions depuis la console de l''éditeur en place : c''est là que se trouvent celles qui comptent.'
            }
            else {
                Add-Finding 'Télémétrie' 'Exclusions antivirus' $ST_UNK $CR_ELEV ('Lecture des préférences Defender impossible. Détail : ' + $_.Exception.Message) 'Relancer en session administrateur.'
            }
        }
    }
}

# --- Règle ASR pilotes vulnérables et posture ASR globale ---
if (-not $defenderActif) {
    Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_NA $CR_ELEV ('Defender en mode « ' + $modeAff + ' » : les règles ASR ne sont pas appliquées.') 'Auditer le contrôle équivalent chez l''éditeur de l''agent primaire.'
    Add-Finding 'Réduction de surface' 'Posture ASR globale' $ST_NA $CR_MOY ('Defender en mode « ' + $modeAff + ' ».') 'Sans objet lorsque Defender n''est pas l''antivirus actif.'
}
else {
    $ruleId = '56a863a9-875e-4185-98a7-b882c64b5ce5'
    try {
        $pref2 = Get-MpPreference -ErrorAction Stop
        $ids = @($pref2.AttackSurfaceReductionRules_Ids)
        $act = @($pref2.AttackSurfaceReductionRules_Actions)

        $idx = -1
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($ids[$i] -and ($ids[$i].ToString().ToLower() -eq $ruleId)) { $idx = $i; break }
        }

        if ($idx -lt 0) {
            Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_KO $CR_ELEV 'Règle non configurée.' 'Activer en mode Bloc. Limite à connaître : cette règle empêche l''écriture d''un pilote vulnérable sur le disque, elle ne bloque pas le chargement d''un pilote déjà présent.'
        }
        else {
            $a = [int] $act[$idx]
            if ($a -eq 1) {
                Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_OK $CR_ELEV 'Règle active en mode Bloc.' 'Limite à connaître : ne bloque pas le chargement d''un pilote vulnérable déjà présent sur le disque.'
            }
            elseif ($a -eq 2) {
                Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_KO $CR_ELEV 'Règle en mode Audit : journalisée mais non bloquante.' 'Basculer en mode Bloc après revue des détections.'
            }
            elseif ($a -eq 6) {
                Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_KO $CR_ELEV 'Règle en mode Avertissement : contournable par l''utilisateur.' 'Basculer en mode Bloc.'
            }
            else {
                Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_KO $CR_ELEV ('Règle désactivée (action ' + $a + ').') 'Activer en mode Bloc.'
            }
        }

        $nbBloc = @($act | Where-Object { [int] $_ -eq 1 }).Count
        $nbAudit = @($act | Where-Object { [int] $_ -eq 2 }).Count

        # Plutôt qu'un décompte arbitraire, on évalue nommément les règles qui
        # ferment des vecteurs d'évasion et de progression. Une posture peut
        # afficher beaucoup de règles en Bloc tout en laissant ouvertes celles
        # qui comptent ici.
        $reglesCles = @{
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Vol d''identifiants LSASS'
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Pilotes vulnérables (déjà évalué)'
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Création de processus par PSExec/WMI'
            '3b576869-a4ec-4529-8536-b80a7769e899' = 'Contenu exécutable Office'
            'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Protection avancée contre les rançongiciels'
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Contenu obfusqué / scripts'
            '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Blocage du redémarrage en mode sans échec'
        }
        $manquantes = @()
        foreach ($rid in $reglesCles.Keys) {
            $j = -1
            for ($k = 0; $k -lt $ids.Count; $k++) { if ($ids[$k] -and $ids[$k].ToString().ToLower() -eq $rid) { $j = $k; break } }
            if ($j -lt 0 -or [int] $act[$j] -ne 1) { $manquantes += $reglesCles[$rid] }
        }

        if ($manquantes.Count -eq 0) {
            Add-Finding 'Réduction de surface' 'Posture ASR globale' $ST_OK $CR_MOY ('Les règles clés liées à l''évasion et à la progression sont en mode Bloc (' + $nbBloc + ' règle(s) en Bloc, ' + $nbAudit + ' en Audit).') 'Aucune action.'
        }
        else {
            Add-Finding 'Réduction de surface' 'Posture ASR globale' $ST_KO $CR_MOY ('Règle(s) clé(s) non appliquée(s) en Bloc : ' + ($manquantes -join ', ') + '. Ensemble : ' + $nbBloc + ' règle(s) en Bloc, ' + $nbAudit + ' en Audit.') 'Prioriser la mise en Bloc des règles ci-dessus : elles ferment des vecteurs directement liés à l''évasion (vol LSASS, scripts obfusqués, exécution Office) plutôt qu''un simple volume de règles. Déployer d''abord en Audit, mesurer, puis basculer.'
        }

        # Règle « bloquer les exécutables peu répandus/récents/non fiables ».
        # Efficace contre les rançongiciels récents, mais faux positifs élevés
        # (outils internes, logiciels métier à faible diffusion) : plusieurs
        # référentiels l'excluent de leurs listes recommandées. Traitée à part,
        # avec un message dédié, pour ne pas pénaliser un choix légitime de
        # l'exclure ni la présenter avec la même sévérité neutre que les autres.
        $ridPreval = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        $jP = -1
        for ($k = 0; $k -lt $ids.Count; $k++) { if ($ids[$k] -and $ids[$k].ToString().ToLower() -eq $ridPreval) { $jP = $k; break } }
        $actP = -1
        if ($jP -ge 0) { $actP = [int] $act[$jP] }
        if ($actP -eq 1) {
            Add-Finding 'Réduction de surface' 'ASR, exécutables peu répandus (prévalence)' $ST_OK $CR_FAIB 'Règle de prévalence en mode Bloc.' 'Efficace contre les rançongiciels récents. Surveiller les faux positifs sur les outils internes et logiciels métier peu diffusés, et maintenir une liste d''exceptions à jour.'
        }
        elseif ($actP -eq 2 -or $actP -eq 6) {
            Add-Finding 'Réduction de surface' 'ASR, exécutables peu répandus (prévalence)' $ST_INFO $CR_INFO 'Règle de prévalence en mode Audit/Avertissement.' 'Bon compromis initial. Cette règle bloque par construction tout exécutable peu répandu ou récent : mesurer longuement l''impact (outils internes, métier) avant toute bascule en Bloc.'
        }
        else {
            Add-Finding 'Réduction de surface' 'ASR, exécutables peu répandus (prévalence)' $ST_INFO $CR_INFO 'Règle de prévalence non activée.' 'À envisager contre les rançongiciels récents, mais son taux de faux positifs est plus élevé que les autres règles clés : la déployer d''abord en Audit sur une période prolongée, constituer la liste d''exceptions, puis décider. Son absence n''est pas en soi une non-conformité.'
        }
    }
    catch {
        Add-Finding 'Anti-BYOVD' 'Règle ASR pilotes vulnérables' $ST_UNK $CR_ELEV ('Lecture des préférences Defender impossible. Détail : ' + $_.Exception.Message) 'Relancer en session administrateur.'
        Add-Finding 'Réduction de surface' 'Posture ASR globale' $ST_UNK $CR_MOY 'Non évaluable.' 'Relancer en session administrateur.'
    }
}


# ===========================================================================
#  AXE 4, TÉLÉMÉTRIE ET SUPERVISION
# ===========================================================================

Write-Host '[4/7] Télémétrie et supervision...' -ForegroundColor DarkCyan

# --- Rattachement Microsoft Defender for Endpoint ---
$mdePath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
$onb = Get-RegValue -Path $mdePath -Name 'OnboardingState'
$svcSense = $null
try { $svcSense = Get-Service -Name 'Sense' -ErrorAction Stop } catch { }

if ($onb.Error) {
    Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_UNK $CR_CRIT ('Clé inaccessible. Détail : ' + $onb.Error) 'Relancer en session administrateur.'
}
elseif ($onb.Found -and [int] $onb.Value -eq 1) {
    $etatSense = 'service Sense absent'
    if ($svcSense) { $etatSense = 'service Sense : ' + $svcSense.Status }
    if ($svcSense -and $svcSense.Status -eq 'Running') {
        # Vérifiable localement : intégration + service de télémétrie actif.
        Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_OK $CR_CRIT ('Machine intégrée à Defender for Endpoint (' + $etatSense + ').') 'Intégration et service de télémétrie confirmés sur la machine.'
        # NON vérifiable localement : la console reçoit-elle réellement ? Même
        # question que pour un agent tiers, donc même état, par symétrie.
        Add-Finding 'Télémétrie' 'Remontée effective vers la console (MDE)' $ST_CONSOLE $CR_CRIT 'L''intégration et le service Sense sont actifs localement, mais la réception effective côté console ne se vérifie pas depuis la machine.' 'Confirmer dans le portail Defender que cette machine est « active » et a communiqué récemment, et que son seuil d''inactivité déclenche une alerte.'
    }
    else {
        Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_KO $CR_CRIT ('Machine intégrée mais ' + $etatSense + '.') 'Une machine intégrée dont le service de télémétrie ne tourne pas est silencieuse côté SOC : traiter comme un incident.'
    }
}
else {
    # Defender Antivirus est présent sur TOUT Windows : sa seule présence ne
    # dit rien du dispositif de supervision en place. Avant de conclure à une
    # machine non supervisée, il faut écarter le cas, majoritaire en parc
    # client, d'un agent tiers en protection primaire, qui remonte vers sa
    # propre console et rend le rattachement MDE hors sujet.
    $agentsTiers = @($agentsDetectes | Where-Object { $_ -ne 'Microsoft Defender' })

    if ($agentsTiers.Count -gt 0 -or -not $defenderActif) {
        $quiSupervise = 'un agent tiers'
        if ($agentsTiers.Count -gt 0) { $quiSupervise = ($agentsTiers -join ', ') }
        Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_NA $CR_CRIT ('Pas d''intégration Defender for Endpoint, et la protection primaire est assurée par ' + $quiSupervise + ' : le rattachement MDE est hors périmètre sur cette machine.') 'Contrôle sans objet ici. La question reste entière côté éditeur : vérifier dans sa console que cette machine émet bien un signal, et qu''un seuil de perte de contact y déclenche une alerte.'
    }
    elseif ($agentsDetectes -contains 'Microsoft Defender') {
        Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_KO $CR_CRIT 'Defender est l''antivirus actif, aucun agent tiers détecté, et la machine n''est pas intégrée à Defender for Endpoint.' 'Machine non supervisée : aucune télémétrie n''est transmise à une console, donc aucune perte de signal ne peut être détectée. Intégrer la machine, ou documenter le dispositif de supervision qui la couvre.'
    }
    else {
        Add-Finding 'Télémétrie' 'Rattachement à une console (MDE)' $ST_UNK $CR_CRIT 'Aucune intégration MDE et aucun agent de sécurité identifié sur la machine.' 'Déterminer quel dispositif supervise cette machine. Une machine sans agent identifié et sans rattachement console est un angle mort complet.'
    }
}

# --- Journalisation PowerShell (couverture ETW / AMSI) ---
$jSbl = Test-JournalisationPS -SousCle 'ScriptBlockLogging' -Valeur 'EnableScriptBlockLogging'
if ($jSbl.Actif) {
    Add-Finding 'Télémétrie' 'Journalisation ScriptBlock PowerShell' $ST_OK $CR_ELEV ('Journalisation des blocs de script active (' + $jSbl.Source + ').') 'Aucune action.'
}
else {
    Add-Finding 'Télémétrie' 'Journalisation ScriptBlock PowerShell' $ST_KO $CR_ELEV 'Journalisation des blocs de script inactive, ni par stratégie de groupe ni en configuration locale.' 'Filet de sécurité utile face au masquage AMSI/ETW : la journalisation ScriptBlock capture le code désobfusqué avant exécution. Elle n''est toutefois pas infaillible, un administrateur peut neutraliser les fournisseurs ETW en mémoire (correctif d''EtwEventWrite) sans toucher au registre. Activer de préférence par stratégie de groupe, pour que le réglage ne soit pas modifiable localement.'
}

$jMod = Test-JournalisationPS -SousCle 'ModuleLogging' -Valeur 'EnableModuleLogging'
if ($jMod.Actif) {
    Add-Finding 'Télémétrie' 'Journalisation des modules PowerShell' $ST_OK $CR_MOY ('Journalisation des modules active (' + $jMod.Source + ').') 'Aucune action.'
}
else {
    Add-Finding 'Télémétrie' 'Journalisation des modules PowerShell' $ST_KO $CR_MOY 'Journalisation des modules inactive, ni par stratégie de groupe ni en configuration locale.' 'Activer, en dimensionnant la rétention du journal en conséquence.'
}

$jTrans = Test-JournalisationPS -SousCle 'Transcription' -Valeur 'EnableTranscripting'
if ($jTrans.Actif) {
    Add-Finding 'Télémétrie' 'Transcription PowerShell' $ST_OK $CR_FAIB ('Transcription active (' + $jTrans.Source + ').') 'Vérifier que le répertoire de destination est protégé en écriture pour les utilisateurs.'
}
else {
    Add-Finding 'Télémétrie' 'Transcription PowerShell' $ST_KO $CR_FAIB 'Transcription inactive, ni par stratégie de groupe ni en configuration locale.' 'Activer vers un partage centralisé en écriture seule pour conserver une trace hors du poste.'
}

# --- Moteur PowerShell v2 (contournement AMSI) ---
$v2 = 'Indetermine'
try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction Stop
    $v2 = [string] $f.State
}
catch {
    $regV2 = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellVersion'
    if ($regV2.Found) { $v2 = 'Enabled' }
}

if ($v2 -eq 'Disabled' -or $v2 -eq 'DisabledWithPayloadRemoved') {
    Add-Finding 'Télémétrie' 'Moteur PowerShell v2' $ST_OK $CR_ELEV 'Moteur PowerShell v2 désactivé.' 'Aucune action.'
}
elseif ($v2 -eq 'Enabled') {
    Add-Finding 'Télémétrie' 'Moteur PowerShell v2' $ST_KO $CR_ELEV 'Moteur PowerShell v2 présent et activé.' 'PowerShell v2 ne supporte ni AMSI ni la journalisation ScriptBlock : son maintien annule les contrôles précédents. Désactiver la fonctionnalité facultative.'
}
else {
    Add-Finding 'Télémétrie' 'Moteur PowerShell v2' $ST_UNK $CR_ELEV 'État de la fonctionnalité non déterminé sur cette édition de Windows.' 'Vérifier manuellement la présence du moteur v2.'
}

# --- Fournisseurs AMSI ---
try {
    $amsi = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction Stop)
    if ($amsi.Count -gt 0) {
        Add-Finding 'Télémétrie' 'Fournisseurs AMSI enregistrés' $ST_PRES $CR_MOY ($amsi.Count.ToString() + ' fournisseur(s) AMSI enregistré(s).') 'Présence confirmée, mais ce contrôle ne valide pas l''intégrité du moteur AMSI en mémoire : un administrateur peut neutraliser l''analyse par correctif d''AmsiScanBuffer sans rien changer au registre. La journalisation ScriptBlock reste le filet de sécurité en cas de contournement.'
    }
    else {
        Add-Finding 'Télémétrie' 'Fournisseurs AMSI enregistrés' $ST_KO $CR_MOY 'Aucun fournisseur AMSI enregistré.' 'Sans fournisseur, l''analyse en mémoire des scripts et macros est inopérante.'
    }
}
catch {
    Add-Finding 'Télémétrie' 'Fournisseurs AMSI enregistrés' $ST_UNK $CR_MOY 'Clé AMSI\Providers inaccessible ou absente.' 'Relancer en session administrateur.'
}

# --- Rétention du journal Sécurité ---
# Seuil paramétrable : un serveur à fort volume d'événements peut consommer
# 512 Mo en quelques heures, un poste standard en plusieurs semaines. La
# valeur n'est donc pas universelle ; elle est surchargeable par
# AGILLY_SEUIL_JOURNAL_MO selon le profil de machine audité.
$seuilJournalMo = 512
if ($env:AGILLY_SEUIL_JOURNAL_MO -and ([int]::TryParse($env:AGILLY_SEUIL_JOURNAL_MO, [ref]([int]0)))) {
    $seuilJournalMo = [int] $env:AGILLY_SEUIL_JOURNAL_MO
}
try {
    $logSec = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    $mo = [math]::Round($logSec.MaximumSizeInBytes / 1MB, 0)
    if ($mo -ge $seuilJournalMo) {
        Add-Finding 'Télémétrie' 'Rétention du journal Sécurité' $ST_OK $CR_MOY ('Taille maximale : ' + $mo + ' Mo (seuil : ' + $seuilJournalMo + ' Mo).') 'Seuil indicatif : le dimensionner sur le volume réel d''événements et la durée de rétention visée, plus élevé sur un serveur qu''un poste.'
    }
    else {
        Add-Finding 'Télémétrie' 'Rétention du journal Sécurité' $ST_KO $CR_MOY ('Taille maximale : ' + $mo + ' Mo (seuil : ' + $seuilJournalMo + ' Mo), insuffisante pour une investigation a posteriori.') 'Porter au moins au seuil, ou externaliser les événements par transfert (WEF) vers un collecteur indépendant de l''agent.'
    }
}
catch {
    Add-Finding 'Télémétrie' 'Rétention du journal Sécurité' $ST_UNK $CR_MOY ('Lecture impossible. Détail : ' + $_.Exception.Message) 'Relancer en session administrateur.'
}


# ===========================================================================
#  AXE 5, HISTORIQUE DES JOURNAUX (30 JOURS)
#  Les autres axes photographient un état à l'instant T. Une machine dont
#  l'agent a été arrêté quatre heures la semaine passée puis redémarré y
#  ressortirait intégralement conforme. Cet axe cherche la trace.
# ===========================================================================

Write-Host '[5/7] Historique des journaux sur 30 jours...' -ForegroundColor DarkCyan

$depuis30 = (Get-Date).AddDays(-30)

# --- Intégrité des journaux : effacement (préalable à tout le reste) ---
# Un journal effacé (System 104, Security 1102) rend cet axe non probant :
# l'absence de trace d'arrêt peut résulter de l'effacement, pas de l'absence
# d'incident. C'est en soi un signal fort et un préalable d'interprétation.
# Le fournisseur DOIT être contraint. L'identifiant 104 n'appartient pas en
# propre au service Eventlog : d'autres fournisseurs écrivent un événement 104
# dans le journal Système. Un filtre portant sur le seul identifiant compte ces
# événements étrangers et fabrique un effacement de journal qui n'a jamais eu
# lieu, constat de criticité maximale rendu sur une machine saine.
$journauxEffaces = $false
$evClrSys = Get-Evenements -Journal 'System'   -Ids @(104)  -Depuis $depuis30 -Fournisseur 'Microsoft-Windows-Eventlog' -Max 50
$evClrSec = Get-Evenements -Journal 'Security' -Ids @(1102) -Depuis $depuis30 -Fournisseur 'Microsoft-Windows-Eventlog' -Max 50
$clrDetail = @()
$clrIllisible = @()
if ($null -ne $evClrSys.Erreur) { $clrIllisible += 'Système' }
elseif ($evClrSys.Evenements.Count -gt 0) { $clrDetail += 'journal Système effacé x' + $evClrSys.Evenements.Count; $journauxEffaces = $true }
# Le journal Sécurité n'est pas lisible sans élévation. Conclure « aucun
# effacement » sur un journal qu'on n'a pas pu ouvrir serait affirmer plus que
# ce qui a été mesuré : l'absence de lecture sort en INDÉTERMINÉ.
if ($null -ne $evClrSec.Erreur) { $clrIllisible += 'Sécurité' }
elseif ($evClrSec.Evenements.Count -gt 0) { $clrDetail += 'journal Sécurité effacé x' + $evClrSec.Evenements.Count; $journauxEffaces = $true }

if ($journauxEffaces) {
    $detClr = 'Effacement de journal relevé : ' + ($clrDetail -join ' ; ') + '. Les constats d''historique ci-dessous ne sont pas probants.'
    if ($clrIllisible.Count -gt 0) { $detClr += ' Journal(aux) non lisible(s) dans cette session : ' + ($clrIllisible -join ', ') + '.' }
    Add-Finding 'Historique' 'Intégrité des journaux (effacement, 30 j)' $ST_TRI $CR_INFO $detClr 'Événement 104 du fournisseur Eventlog (journal effacé) ou 1102 (journal Sécurité effacé). Identifier l''auteur et la date dans l''événement lui-même, puis rapprocher d''une opération déclarée, réinitialisation de poste, intervention de maintenance, remise en service. Sans justification, traiter comme un incident d''anti-investigation.'
}
elseif ($clrIllisible.Count -gt 0) {
    Add-Finding 'Historique' 'Intégrité des journaux (effacement, 30 j)' $ST_UNK $CR_INFO ('Journal(aux) non lisible(s) dans cette session : ' + ($clrIllisible -join ', ') + '. L''absence d''effacement ne peut pas être établie.') 'Relancer en session administrateur.'
}
else {
    Add-Finding 'Historique' 'Intégrité des journaux (effacement, 30 j)' $ST_OK $CR_INFO 'Aucun effacement des journaux Système ou Sécurité relevé sur la période.' 'Aucune action.'
}

# --- Arrêts, plantages et reconfigurations de services de sécurité ---
# 7036/7040 : arrêt/changement de type de démarrage (voie propre du SCM).
# 7031/7034 : arrêt INATTENDU (plantage). Le processus n'est pas toujours
# emprunté proprement : un crash provoqué est un signal distinct et pertinent.
if ($servicesSecurite.Count -gt 0) {
    $motifsSvc = ($servicesSecurite | ForEach-Object { [regex]::Escape($_.DisplayName) }) -join '|'
    $nomsSvc   = ($servicesSecurite | ForEach-Object { [regex]::Escape($_.Name) }) -join '|'
    $evSvc = Get-Evenements -Journal 'System' -Ids @(7031, 7034, 7036, 7040) -Depuis $depuis30 -Max 6000

    if ($evSvc.Erreur) {
        Add-Finding 'Historique' 'Arrêts de services de sécurité (30 j)' $ST_UNK $CR_INFO ('Lecture du journal Système impossible. Détail : ' + $evSvc.Erreur) 'Relancer en session administrateur.'
    }
    else {
        $pertinents = @($evSvc.Evenements | Where-Object {
            $_.Message -and ($_.Message -match $motifsSvc -or $_.Message -match $nomsSvc) -and
            ($_.Id -eq 7040 -or $_.Id -eq 7031 -or $_.Id -eq 7034 -or $_.Message -match 'arr.t|stopped|disabled|d.sactiv')
        })
        $plantages = @($pertinents | Where-Object { $_.Id -eq 7031 -or $_.Id -eq 7034 })
        $noteTronq = ''
        if ($evSvc.Tronque) { $noteTronq = ' Plafond de lecture atteint : la période de 30 jours n''est peut-être pas entièrement couverte, l''absence de trace n''est donc pas garantie.' }

        if ($pertinents.Count -eq 0) {
            $etatSvc = $ST_OK
            $detSvc = 'Aucun arrêt, plantage ni changement de type de démarrage relevé sur les services de sécurité.'
            if ($evSvc.Tronque) { $etatSvc = $ST_PRES; $detSvc = 'Aucun événement pertinent dans la fenêtre lue, mais le plafond de lecture a été atteint : couverture partielle.' }
            Add-Finding 'Historique' 'Arrêts de services de sécurité (30 j)' $etatSvc $CR_INFO $detSvc 'Aucune action, sous réserve de la couverture indiquée.'
        }
        else {
            $recents = @($pertinents | Sort-Object TimeCreated -Descending | Select-Object -First 5)
            $resume = ($recents | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ' (ID ' + $_.Id + ')' }) -join ' ; '
            # Annoncer « cinq plus récents » devant trois lignes est une erreur
            # visible par le destinataire de l'audit, qui compte.
            $libRecents = ' Cinq plus récents : '
            if ($recents.Count -lt 5) { $libRecents = ' ' + $recents.Count + ' occurrence(s) : ' }

            # Répartition par service : une centaine d'événements concentrés sur
            # un seul service est un problème de stabilité, pas une campagne de
            # sabotage. Sans cette ventilation, le constat n'est pas exploitable.
            $parService = @{}
            foreach ($ev in $pertinents) {
                $nomTrouve = ''
                foreach ($sv in $servicesSecurite) {
                    if ($ev.Message -and ($ev.Message -match [regex]::Escape($sv.DisplayName) -or $ev.Message -match [regex]::Escape($sv.Name))) {
                        $nomTrouve = $sv.DisplayName; break
                    }
                }
                if ($nomTrouve -eq '') { $nomTrouve = 'service non identifié' }
                if ($parService.ContainsKey($nomTrouve)) { $parService[$nomTrouve] = $parService[$nomTrouve] + 1 }
                else { $parService[$nomTrouve] = 1 }
            }
            $classe = @($parService.GetEnumerator() | Sort-Object Value -Descending)
            $topSvc = @($classe | Select-Object -First 4 | ForEach-Object { $_.Key + ' x' + $_.Value })
            $detRepartition = ' Répartition : ' + ($topSvc -join ' ; ') + '.'
            $detPlant = ''
            if ($plantages.Count -gt 0) { $detPlant = ' Dont ' + $plantages.Count + ' arrêt(s) INATTENDU(s) (7031/7034), signal d''un plantage possiblement provoqué.' }

            # Règle de concentration. C'est la DIVERSITÉ qui porte le signal, pas
            # le volume : soixante-trois redémarrages d'un même agent décrivent la
            # stabilité d'un produit, trois services de sécurité distincts arrêtés
            # dans la même heure décrivent une neutralisation. Sans cette lecture,
            # tout poste doté d'un agent bavard sort en écart et le constat perd
            # sa valeur d'alerte à force de se déclencher partout.
            $partDominante = 0
            $nomDominant = ''
            if ($classe.Count -gt 0 -and $pertinents.Count -gt 0) {
                $partDominante = [math]::Round(($classe[0].Value / $pertinents.Count) * 100)
                $nomDominant = $classe[0].Key
            }
            # Regarder le seul service de tête ne suffit pas : deux agents
            # bavards se partageant 80 % du volume donnent un premier à 56 %,
            # donc « pas de service dominant », et le constat désignerait comme
            # diversité ce qui est du bruit de deux produits. On mesure donc
            # aussi le peloton de tête.
            $partTeteDeux = 0
            if ($classe.Count -ge 2 -and $pertinents.Count -gt 0) {
                $partTeteDeux = [math]::Round((($classe[0].Value + $classe[1].Value) / $pertinents.Count) * 100)
            }
            $detConcentration = ''
            if ($partDominante -ge 70) {
                $detConcentration = ' Concentration : ' + $partDominante + ' % des événements portent sur « ' + $nomDominant + ' », profil d''instabilité ou de cycle de mise à jour d''un seul produit, et non de neutralisation coordonnée.'
            }
            elseif ($partTeteDeux -ge 80) {
                $detConcentration = ' Concentration : ' + $partTeteDeux + ' % des événements portent sur deux services (« ' + $classe[0].Key + ' » et « ' + $classe[1].Key + ' »), profil d''instabilité ou de cycle de mise à jour de ces produits, et non de neutralisation coordonnée.'
            }
            elseif ($classe.Count -ge 3) {
                $detConcentration = ' Répartition étalée sur ' + $classe.Count + ' service(s) distinct(s), sans produit dominant (tête de classement : ' + $partTeteDeux + ' % sur deux services) : c''est le profil qui justifie une lecture chronologique en priorité.'
            }

            Add-Finding 'Historique' 'Arrêts de services de sécurité (30 j)' $ST_TRI $CR_INFO ($pertinents.Count.ToString() + ' événement(s) d''arrêt, de plantage ou de reconfiguration.' + $detRepartition + $detConcentration + $libRecents + $resume + '.' + $detPlant + $noteTronq) 'Lire d''abord la concentration, ensuite la chronologie. Rapprocher chaque occurrence d''une fenêtre de maintenance déclarée : un arrêt hors fenêtre est un incident, un arrêt dans la fenêtre ne l''est pas, distinction que ce script ne peut pas faire, d''où le statut À TRIER. Rappel : une terminaison depuis le noyau ne passe pas par le gestionnaire de services et ne génère aucun de ces événements, l''absence de trace ne prouve donc rien.'
        }
    }
}

# --- Journal opérationnel Defender ---
$evDef = Get-Evenements -Journal 'Microsoft-Windows-Windows Defender/Operational' -Ids @(5001, 5007, 5010, 5012) -Depuis $depuis30 -Max 2000
if ($evDef.Erreur) {
    Add-Finding 'Historique' 'Désactivations de protection Defender (30 j)' $ST_UNK $CR_INFO ('Journal Defender illisible ou absent. Détail : ' + $evDef.Erreur) 'Sur un poste sous agent tiers, extraire l''équivalent depuis la console de l''éditeur.'
}
elseif ($evDef.Evenements.Count -eq 0) {
    Add-Finding 'Historique' 'Désactivations de protection Defender (30 j)' $ST_OK $CR_INFO 'Aucune désactivation de protection ni modification de configuration relevée.' 'Aucune action.'
}
else {
    $parId = $evDef.Evenements | Group-Object Id | ForEach-Object { 'ID ' + $_.Name + ' x' + $_.Count }
    $dernier = (@($evDef.Evenements | Sort-Object TimeCreated -Descending)[0]).TimeCreated.ToString('yyyy-MM-dd HH:mm')
    if ($agentTiersPrimaire) {
        Add-Finding 'Historique' 'Désactivations de protection Defender (30 j)' $ST_INFO $CR_INFO ($evDef.Evenements.Count.ToString() + ' événement(s) : ' + ($parId -join ', ') + '. Le plus récent le ' + $dernier + '. Sur une machine protégée par ' + $nomAgentTiers + ', les modifications de configuration Defender (ID 5007) sont en grande partie produites par la bascule en mode passif et par l''agent lui-même.') 'Ne pas conclure sans tri. Les occurrences à retenir sont celles de type 5001 (protection temps réel désactivée) et celles qui ne coïncident ni avec une installation, ni avec une mise à jour de l''agent. L''équivalent côté éditeur s''extrait depuis sa console.'
    }
    else {
        Add-Finding 'Historique' 'Désactivations de protection Defender (30 j)' $ST_TRI $CR_INFO ($evDef.Evenements.Count.ToString() + ' événement(s) : ' + ($parId -join ', ') + '. Le plus récent le ' + $dernier + '.') 'ID 5001 : protection temps réel désactivée. ID 5007 : configuration modifiée, y compris l''ajout d''exclusions. Identifier l''auteur et le contexte de chaque occurrence.'
    }
}

# --- Refus de chargement de pilotes (intégrité du code) ---
$evCi = Get-Evenements -Journal 'Microsoft-Windows-CodeIntegrity/Operational' -Ids @(3033, 3077) -Depuis $depuis30 -Max 2000
if ($evCi.Erreur) {
    Add-Finding 'Historique' 'Refus de chargement de pilotes (30 j)' $ST_UNK $CR_INFO ('Journal CodeIntegrity illisible. Détail : ' + $evCi.Erreur) 'Relancer en session administrateur.'
}
elseif ($evCi.Evenements.Count -eq 0) {
    Add-Finding 'Historique' 'Refus de chargement de pilotes (30 j)' $ST_INFO $CR_INFO 'Aucun refus de chargement journalisé.' 'Résultat attendu sur un poste sain. Ce journal reste la source à consulter en cas de suspicion de BYOVD.'
}
else {
    $dernierCi = (@($evCi.Evenements | Sort-Object TimeCreated -Descending)[0]).TimeCreated.ToString('yyyy-MM-dd HH:mm')

    # Un compte brut n'est pas exploitable : plusieurs centaines de refus portent
    # presque toujours sur le même binaire, rejeté en boucle. Extraire le nom du
    # fichier transforme le constat en action.
    $binairesCi = @{}
    foreach ($ev in @($evCi.Evenements | Select-Object -First 300)) {
        $nomBin = 'binaire non identifié'
        if ($ev.Message) {
            $mBin = [regex]::Match($ev.Message, '(?i)[^\\/:*?"<>|\r\n]+\.(sys|dll|exe)')
            if ($mBin.Success) { $nomBin = $mBin.Value }
        }
        if ($binairesCi.ContainsKey($nomBin)) { $binairesCi[$nomBin] = $binairesCi[$nomBin] + 1 }
        else { $binairesCi[$nomBin] = 1 }
    }
    # Les composants Windows signés Microsoft sont refusés en boucle par la
    # politique d'intégrité par défaut : svchost.exe à lui seul représente
    # couramment l'essentiel du volume. Les compter dans le constat principal
    # noie le seul cas qui intéresse ici, un pilote tiers inconnu refusé une
    # fois. Ils sont donc restitués à part, jamais supprimés.
    $binSysteme = '^(svchost|services|lsass|wininit|csrss|smss|winlogon|spoolsv|dllhost|taskhostw|sihclient|securityhealthservice|msmpeng|mpdefendercoreservice|searchindexer|runtimebroker|wudfhost|dwm|explorer|conhost|backgroundtaskhost|sppsvc|trustedinstaller|tiworker)\.exe$'
    $binHorsSysteme = @{}
    $nbSysteme = 0
    foreach ($k in $binairesCi.Keys) {
        if ($k -match $binSysteme) { $nbSysteme += $binairesCi[$k] }
        else { $binHorsSysteme[$k] = $binairesCi[$k] }
    }
    $topBin = @($binHorsSysteme.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 4 | ForEach-Object { $_.Key + ' x' + $_.Value })
    $detBin = ''
    # L'échantillon doit être nommé : afficher « 300 refus portent sur des
    # composants Windows » à côté d'un total de 635 laisse croire que les 335
    # autres sont inconnus, alors qu'ils n'ont simplement pas été dépouillés.
    $nbEchantillon = @($evCi.Evenements | Select-Object -First 300).Count
    $detBin = ' Analyse portant sur les ' + $nbEchantillon + ' événement(s) les plus récents.'
    if ($nbSysteme -gt 0) {
        $partSys = [math]::Round(($nbSysteme / $nbEchantillon) * 100)
        $detBin += ' ' + $nbSysteme + ' d''entre eux (' + $partSys + ' %) portent sur des composants Windows signés Microsoft, rejetés en boucle par la politique d''intégrité par défaut : bruit de fond attendu.'
    }
    if ($topBin.Count -gt 0) { $detBin += ' Binaires hors composants Windows les plus refusés : ' + ($topBin -join ' ; ') + '.' }
    else { $detBin += ' Aucun binaire hors composants Windows dans cet échantillon.' }

    Add-Finding 'Historique' 'Refus de chargement de pilotes (30 j)' $ST_TRI $CR_INFO ($evCi.Evenements.Count.ToString() + ' refus de chargement par le contrôle d''intégrité. Le plus récent le ' + $dernierCi + '.' + $detBin) 'Ignorer le volume, lire la liste hors composants Windows. Un volume élevé concentré sur un même fichier traduit une incompatibilité persistante entre un logiciel installé et la politique d''intégrité. Le signal à investiguer en priorité est l''inverse : un refus isolé sur un pilote tiers inconnu.'
}

# --- Installation de services pilotes noyau (30 j) ---
# L'inventaire à l'instant T ne voit qu'un pilote encore chargé. Les outils de
# type kdmapper déchargent et effacent le pilote après usage : la détection
# des orphelins passe alors à côté. L'événement 7045 (installation d'un
# service, avec type) survit au déchargement et garde la trace historique.
$evNewSvc = Get-Evenements -Journal 'System' -Ids @(7045) -Depuis $depuis30 -Fournisseur 'Service Control Manager' -Max 3000
if ($evNewSvc.Erreur) {
    Add-Finding 'Historique' 'Installation de pilotes noyau (30 j)' $ST_UNK $CR_INFO ('Lecture du journal Système impossible. Détail : ' + $evNewSvc.Erreur) 'Relancer en session administrateur.'
}
else {
    # On ne retient que les services de type pilote noyau. Le motif exige la
    # cooccurrence « pilote … noyau » (ou « kernel mode driver ») plutôt qu'un
    # « noyau » isolé qui matcherait un message sans rapport par coïncidence.
    $pilotesInstalles = @($evNewSvc.Evenements | Where-Object { $_.Message -and $_.Message -match 'kernel mode driver|pilote.{0,12}noyau' })
    $noteTronqDrv = ''
    if ($evNewSvc.Tronque) { $noteTronqDrv = ' Plafond de lecture atteint : couverture partielle de la période.' }
    if ($pilotesInstalles.Count -eq 0) {
        $etatDrv = $ST_OK
        if ($evNewSvc.Tronque) { $etatDrv = $ST_PRES }
        Add-Finding 'Historique' 'Installation de pilotes noyau (30 j)' $etatDrv $CR_ELEV ('Aucune installation de service pilote noyau relevée sur la période.' + $noteTronqDrv) 'Aucune action, sous réserve de la couverture indiquée.'
    }
    else {
        $recentsDrv = @($pilotesInstalles | Sort-Object TimeCreated -Descending | Select-Object -First 5)
        $resumeDrv = ($recentsDrv | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) -join ' ; '
        $libDrv = ' Cinq plus récentes : '
        if ($recentsDrv.Count -lt 5) { $libDrv = ' Horodatage(s) : ' }
        Add-Finding 'Historique' 'Installation de pilotes noyau (30 j)' $ST_TRI $CR_INFO ($pilotesInstalles.Count.ToString() + ' installation(s) de service pilote noyau.' + $libDrv + $resumeDrv + '.' + $noteTronqDrv) 'Toute installation de pilote noyau n''est pas malveillante (mises à jour, agents). Rapprocher chaque entrée d''un changement légitime ; une installation isolée, hors cycle de mise à jour, suivie d''une disparition du pilote, est le motif du BYOVD.'
    }
}

# --- Collecteur indépendant de l'agent ---
# Si l'agent meurt, plus rien ne remonte ses journaux. Un collecteur
# indépendant est un prérequis d'architecture de la détection de silence.
# Principe du script : une clé présente ne prouve pas une collecte active.
# On lit donc les valeurs sous SubscriptionManager (une URL de serveur y est
# attendue), et on distingue Sysmon, qui journalise localement, d'un vrai
# transfert hors machine.
$wefPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
$wefConfigure = $false
$wefCle = Test-Path -LiteralPath $wefPath
if ($wefCle) {
    try {
        $k = Get-Item -LiteralPath $wefPath -ErrorAction Stop
        # Les abonnements sont des valeurs numérotées contenant « Server=... ».
        foreach ($vn in $k.GetValueNames()) {
            if ([string] $k.GetValue($vn) -match 'Server\s*=') { $wefConfigure = $true; break }
        }
    }
    catch { }
}
$sysmonActif = ($collecteursDetectes -contains 'Sysmon')

if ($wefConfigure) {
    $comp = ''
    if ($sysmonActif) { $comp = ' Sysmon également présent comme source d''événements.' }
    Add-Finding 'Historique' 'Collecteur indépendant de l''agent' $ST_OK $CR_ELEV ('Abonnement de transfert d''événements (WEF) configuré vers un collecteur.' + $comp) 'Confirmer côté collecteur que les événements de cette machine y arrivent effectivement.'
}
elseif ($wefCle -or $sysmonActif) {
    # Présence sans preuve de transfert effectif hors machine.
    $motif = @()
    if ($wefCle) { $motif += 'clé de stratégie WEF présente mais sans URL de serveur d''abonnement' }
    if ($sysmonActif) { $motif += 'Sysmon présent (journalisation locale), sans preuve de transfert vers un collecteur distant' }
    Add-Finding 'Historique' 'Collecteur indépendant de l''agent' $ST_PRES $CR_ELEV ('Éléments présents mais transfert effectif non établi : ' + ($motif -join ' ; ') + '.') 'Un journal qui reste sur la machine ne survit pas à sa compromission. Configurer un abonnement WEF vers un collecteur distant (valeur Server=... sous SubscriptionManager), et pour Sysmon, s''assurer que ses événements sont transférés hors du poste.'
}
else {
    if ($horsDomaine) {
        Add-Finding 'Historique' 'Collecteur indépendant de l''agent' $ST_NA $CR_ELEV ('Aucun transfert d''événements ni collecteur tiers détecté, sur une machine hors domaine (' + $domaine + ').') 'Contrôle sans objet sur un poste isolé : la collecte WEF suppose une infrastructure de collecte. La limite demeure, si l''agent est neutralisé, la preuve reste sur la machine, et le contrôle redevient pleinement applicable dès l''intégration à un parc supervisé.'
    }
    else {
        Add-Finding 'Historique' 'Collecteur indépendant de l''agent' $ST_KO $CR_ELEV 'Aucun transfert d''événements ni collecteur tiers détecté.' 'Sans collecteur indépendant, les journaux de cette machine ne quittent le poste que par l''agent lui-même. Si l''agent est neutralisé, la preuve de sa neutralisation reste sur la machine compromise. Déployer un abonnement WEF vers un collecteur, ou Sysmon avec transfert.'
    }
}


# ===========================================================================
#  AXE 6, PRIVILÈGES
# ===========================================================================

Write-Host '[6/7] Privilèges et comptes...' -ForegroundColor DarkCyan

$adm = Get-AdminsLocaux

if ($adm.Membres.Count -eq 0) {
    Add-Finding 'Privilèges' 'Composition du groupe Administrateurs locaux' $ST_UNK $CR_CRIT ('Énumération impossible. Détail : ' + $adm.Error) 'Relancer en session administrateur, ou auditer via l''annuaire.'
}
else {
    # Analyse de composition, et non simple décompte : sur une machine jointe
    # au domaine, trois à quatre entrées sont normales.
    $motifLarge = 'Everyone|Tout le monde|Authenticated Users|Utilisateurs authentifiés|Domain Users|Utilisateurs du domaine|INTERACTIVE|INTERACTIF|Users$|Utilisateurs$'
    $large = @($adm.Membres | Where-Object { $_ -match $motifLarge })

    $motifAttendu = 'Domain Admins|Admins du domaine|Administrator$|Administrateur$|Enterprise Admins'
    $inattendus = @($adm.Membres | Where-Object { $_ -notmatch $motifAttendu -and $_ -notmatch $motifLarge })

    $liste = $adm.Membres -join ' ; '

    if ($large.Count -gt 0) {
        Add-Finding 'Privilèges' 'Composition du groupe Administrateurs locaux' $ST_KO $CR_CRIT ('Groupe à portée large présent : ' + ($large -join ' ; ') + '. Composition complète : ' + $liste) 'Un groupe large dans les administrateurs locaux donne à tout utilisateur les privilèges nécessaires au chargement d''un pilote. C''est la condition d''entrée de la chaîne BYOVD. À retirer en priorité.'
    }
    elseif ($inattendus.Count -gt 2) {
        Add-Finding 'Privilèges' 'Composition du groupe Administrateurs locaux' $ST_KO $CR_CRIT ($inattendus.Count.ToString() + ' entrée(s) hors schéma d''administration standard : ' + ($inattendus -join ' ; ') + '. Composition complète : ' + $liste) 'Revoir la justification de chaque compte nominatif. Sans droits d''administration locale, la chaîne d''évasion noyau ne peut pas démarrer.'
    }
    else {
        Add-Finding 'Privilèges' 'Composition du groupe Administrateurs locaux' $ST_OK $CR_CRIT ('Composition conforme au schéma d''administration standard (' + $adm.Membres.Count + ' entrée(s), méthode : ' + $adm.Methode + ') : ' + $liste) 'Maintenir, et vérifier la rotation des mots de passe du compte administrateur local.'
    }
}

# --- LAPS ---
$lapsNatif = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory'
$lapsLegacy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Name 'AdmPwdEnabled'

if ($lapsNatif.Found -and (@(1, 2) -contains [int] $lapsNatif.Value)) {
    $cible = 'Active Directory'
    if ([int] $lapsNatif.Value -eq 1) { $cible = 'Microsoft Entra ID' }
    Add-Finding 'Privilèges' 'Rotation du mot de passe administrateur local (LAPS)' $ST_OK $CR_ELEV ('Windows LAPS actif, sauvegarde vers ' + $cible + '.') 'Aucune action.'
}
elseif ($lapsLegacy.Found -and [int] $lapsLegacy.Value -eq 1) {
    Add-Finding 'Privilèges' 'Rotation du mot de passe administrateur local (LAPS)' $ST_OK $CR_ELEV 'LAPS hérité (AdmPwd) actif.' 'Planifier la migration vers Windows LAPS natif.'
}
else {
    if ($horsDomaine) {
        Add-Finding 'Privilèges' 'Rotation du mot de passe administrateur local (LAPS)' $ST_NA $CR_ELEV ('Aucune solution de rotation détectée, sur une machine hors domaine (' + $domaine + ').') 'Contrôle sans objet sur un poste isolé : LAPS suppose un annuaire de sauvegarde (Active Directory ou Entra ID). À réévaluer dès que la machine rejoint un parc géré, c''est là que le mot de passe administrateur local partagé devient le vecteur de déplacement latéral.'
    }
    else {
        Add-Finding 'Privilèges' 'Rotation du mot de passe administrateur local (LAPS)' $ST_KO $CR_ELEV 'Aucune solution de rotation détectée.' 'Un mot de passe administrateur local identique sur le parc permet le déplacement latéral immédiat après compromission d''un seul poste.'
    }
}

# --- UAC ---
$polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$enableLua = Get-RegValue -Path $polSys -Name 'EnableLUA'
$consent = Get-RegValue -Path $polSys -Name 'ConsentPromptBehaviorAdmin'

if ($enableLua.Found -and [int] $enableLua.Value -eq 0) {
    Add-Finding 'Privilèges' 'Contrôle de compte d''utilisateur (UAC)' $ST_KO $CR_ELEV 'UAC désactivé (EnableLUA = 0).' 'Toute exécution s''effectue avec les privilèges complets sans consentement. Réactiver.'
}
elseif ($consent.Found -and [int] $consent.Value -eq 0) {
    Add-Finding 'Privilèges' 'Contrôle de compte d''utilisateur (UAC)' $ST_KO $CR_ELEV 'UAC actif mais élévation silencieuse (ConsentPromptBehaviorAdmin = 0).' 'Positionner sur demande de consentement ou d''identifiants sur le bureau sécurisé.'
}
elseif ($enableLua.Error) {
    Add-Finding 'Privilèges' 'Contrôle de compte d''utilisateur (UAC)' $ST_UNK $CR_ELEV ('Clé inaccessible. Détail : ' + $enableLua.Error) 'Relancer en session administrateur.'
}
else {
    Add-Finding 'Privilèges' 'Contrôle de compte d''utilisateur (UAC)' $ST_OK $CR_ELEV 'UAC actif avec demande de consentement.' 'Aucune action.'
}


# ===========================================================================
#  AXE 7, INVENTAIRE DES PILOTES NOYAU TIERS
# ===========================================================================

if ($ScanDrivers -and $processus32SurOs64) {
    # Sous WOW64, System32\drivers est redirigé vers SysWOW64 : Test-Path
    # échouerait sur la quasi-totalité des pilotes et produirait un parc entier
    # de faux orphelins critiques. On refuse l'inventaire plutôt que d'émettre
    # un faux positif, et on demande une relance en 64 bits.
    Write-Host '[7/7] Inventaire des pilotes noyau tiers : ignoré (processus 32 bits)...' -ForegroundColor DarkYellow
    Add-Finding 'Anti-BYOVD' 'Inventaire des pilotes noyau tiers' $ST_UNK $CR_CRIT 'Processus PowerShell 32 bits sur un OS 64 bits : la redirection WOW64 fausse la résolution des chemins de pilotes. Inventaire, détection d''orphelins et correspondance LOLDrivers non fiables dans ce mode, donc non exécutés.' 'Relancer l''audit avec le PowerShell 64 bits (System32\WindowsPowerShell\v1.0\powershell.exe). En déploiement RMM, forcer l''exécution en 64 bits.'
}
elseif ($ScanDrivers) {
    Write-Host '[7/7] Inventaire des pilotes noyau tiers (peut durer une minute)...' -ForegroundColor DarkCyan


    # --- Localisation de la liste d'empreintes -----------------------------
    $cheminListe = ''
    if ($LolDriversPath -ne '' -and (Test-Path -LiteralPath $LolDriversPath)) {
        $cheminListe = $LolDriversPath
    }
    else {
        $pistes = @()
        try {
            if ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
                $pistes += (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'AGILLY_LOLDrivers_Empreintes.csv')
            }
        }
        catch { }
        if ($dossierRetenu -ne '') { $pistes += (Join-Path $dossierRetenu 'AGILLY_LOLDrivers_Empreintes.csv') }
        $pistes += (Join-Path (Get-Location).Path 'AGILLY_LOLDrivers_Empreintes.csv')
        foreach ($piste in $pistes) {
            if ($piste -and (Test-Path -LiteralPath $piste)) { $cheminListe = $piste; break }
        }
    }

    # --- Chargement --------------------------------------------------------
    # Index unique : empreinte (minuscules) -> annotation. Les trois
    # algorithmes cohabitent dans le même index, la longueur suffisant à
    # les distinguer sans ambiguïté.
    $lolIndex = @{}
    $lolCharge = $false
    $lolSource = ''
    $lolShaVerifie = $false
    $lolStructure = $false

    # --- Empreinte attendue : reprise du fichier .sha256 adjacent ----------
    # Uniquement si aucune valeur n'a été imposée (constante ou variable
    # d'environnement) : une empreinte fournie par l'exploitant l'emporte
    # toujours sur celle trouvée à côté du fichier.
    $lolShaAttendu = $LolDriversSha256
    $lolShaOrigine = 'valeur imposée'
    if ($cheminListe -ne '' -and $lolShaAttendu -eq '') {
        try {
            $cheminSha = $cheminListe + '.sha256'
            if (-not (Test-Path -LiteralPath $cheminSha)) {
                # Variante « nom sans extension » : liste.csv -> liste.sha256
                $cheminSha = [IO.Path]::ChangeExtension($cheminListe, 'sha256')
            }
            if (Test-Path -LiteralPath $cheminSha) {
                $contenuSha = (Get-Content -LiteralPath $cheminSha -TotalCount 4 -ErrorAction Stop) -join ' '
                $mSha = [regex]::Match($contenuSha, '(?i)\b[a-f0-9]{64}\b')
                if ($mSha.Success) {
                    $lolShaAttendu = $mSha.Value.ToLower()
                    $lolShaOrigine = 'fichier ' + (Split-Path -Leaf $cheminSha)
                }
                else {
                    Add-Erreur 'Liste d''empreintes' ('Fichier ' + (Split-Path -Leaf $cheminSha) + ' présent mais ne contenant aucune empreinte SHA256 exploitable.')
                }
            }
        }
        catch {
            Add-Erreur 'Liste d''empreintes' ('Lecture du fichier .sha256 impossible : ' + $_.Exception.Message)
        }
    }

    # Vérification d'intégrité avant usage
    if ($cheminListe -ne '' -and $lolShaAttendu -ne '') {
        try {
            $hListe = (Get-FileHash -LiteralPath $cheminListe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($hListe -ne $lolShaAttendu.ToLower()) {
                Add-Erreur 'Liste d''empreintes' ('Empreinte du fichier de référence non conforme à la valeur attendue (' + $lolShaOrigine + ') : fichier écarté.')
                $cheminListe = ''
            }
            else {
                $lolShaVerifie = $true
            }
        }
        catch {
            Add-Erreur 'Liste d''empreintes' ('Vérification d''intégrité impossible : ' + $_.Exception.Message)
            $cheminListe = ''
        }
    }

    if ($cheminListe -ne '') {
        try {
            $premiereLigne = (Get-Content -LiteralPath $cheminListe -TotalCount 1 -ErrorAction Stop)
            if ($premiereLigne -match 'algo\s*;\s*empreinte') {
                # Format consolidé AGILLY
                $lolStructure = $true
                $lignesListe = Import-Csv -LiteralPath $cheminListe -Delimiter ';' -ErrorAction Stop
                foreach ($l in $lignesListe) {
                    $h = ''
                    if ($l.empreinte) { $h = $l.empreinte.Trim().ToLower() }
                    if ($h -eq '') { continue }
                    if (-not $lolIndex.ContainsKey($h)) {
                        $annot = ''
                        if ($l.pilote) { $annot = $l.pilote }
                        if ($l.hvci -eq 'CHARGE_MALGRE_HVCI') {
                            if ($annot -ne '') { $annot += ', ' }
                            $annot += 'se charge malgré HVCI'
                        }
                        $lolIndex[$h] = $annot
                    }
                }
            }
            else {
                # Export brut : extraction par motif, SHA256 uniquement
                $brut = Get-Content -LiteralPath $cheminListe -Raw -ErrorAction Stop
                $trouves = [regex]::Matches($brut, '(?i)\b[a-f0-9]{64}\b')
                foreach ($m in $trouves) {
                    $h = $m.Value.ToLower()
                    if (-not $lolIndex.ContainsKey($h)) { $lolIndex[$h] = '' }
                }
            }
            $lolCharge = ($lolIndex.Count -ge $LolDriversMinimum)
            $lolSource = Split-Path -Leaf $cheminListe
            if (-not $lolCharge) {
                Add-Erreur 'Liste d''empreintes' ('Seulement ' + $lolIndex.Count + ' entrée(s) chargée(s), minimum attendu ' + $LolDriversMinimum + ' : fichier considéré comme tronqué.')
            }
        }
        catch {
            Add-Erreur 'Chargement de la liste d''empreintes' $_.Exception.Message
        }
    }

    if ($lolCharge) {
        $modeListe = 'SHA256 seul'
        if ($lolStructure) { $modeListe = 'MD5, SHA1 et SHA256' }
        $mentionSha = 'empreinte non vérifiée'
        if ($lolShaVerifie) { $mentionSha = 'empreinte vérifiée - ' + $lolShaOrigine }
        Write-Host ('      Liste chargée : ' + $lolIndex.Count + ' empreinte(s) depuis ' + $lolSource + ' (' + $modeListe + ', ' + $mentionSha + ')') -ForegroundColor DarkGray

        # Fraîcheur : le volume et l'intégrité ne disent rien de l'ancienneté.
        # Une liste volumineuse mais périmée passe les autres contrôles sans
        # alerte, alors que de nouveaux pilotes vulnérables sortent en continu.
        try {
            $ageListe = (New-TimeSpan -Start (Get-Item -LiteralPath $cheminListe).LastWriteTime -End (Get-Date)).Days
            if ($ageListe -gt 180) {
                Add-Finding 'Anti-BYOVD' 'Fraîcheur de la liste d''empreintes' $ST_KO $CR_MOY ('La liste d''empreintes date de ' + $ageListe + ' jour(s) (> 180). La correspondance ne couvre pas les pilotes vulnérables recensés depuis.') 'Actualiser le fichier depuis le référentiel LOLDrivers. La détection par empreinte ne vaut que par la fraîcheur du référentiel.'
            }
            else {
                Add-Finding 'Anti-BYOVD' 'Fraîcheur de la liste d''empreintes' $ST_OK $CR_MOY ('Liste d''empreintes datée de ' + $ageListe + ' jour(s).') 'Maintenir l''actualisation trimestrielle.'
            }
        }
        catch {
            Add-Finding 'Anti-BYOVD' 'Fraîcheur de la liste d''empreintes' $ST_UNK $CR_MOY 'Date de la liste d''empreintes illisible.' 'Vérifier la date du fichier et l''actualiser si nécessaire.'
        }
    }

    $pilotesTiers = @()
    $pilotesNonSignes = @()
    $pilotesVulnerables = @()
    $pilotesOrphelins = @()

    try {
        $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' })
        $n = 0
        foreach ($drv in $drivers) {
            $n++
            if ($drivers.Count -gt 0) {
                $pct = [int] (($n / $drivers.Count) * 100)
                Write-Progress -Activity 'Analyse des pilotes noyau' -Status $drv.Name -PercentComplete $pct
            }

            $chemin = Resolve-DriverPath $drv.PathName

            # Un pilote en exécution dont le fichier a disparu du disque est
            # la signature du BYOVD tel qu'il est pratiqué : dépôt,
            # chargement, exploitation, effacement. Ignorer ce cas
            # reviendrait à jeter le signal le plus fort disponible.
            if (-not $chemin -or -not (Test-Path -LiteralPath $chemin -ErrorAction SilentlyContinue)) {
                $orph = New-Object PSObject
                Add-Member -InputObject $orph -MemberType NoteProperty -Name Nom -Value $drv.Name
                Add-Member -InputObject $orph -MemberType NoteProperty -Name Chemin -Value ([string] $drv.PathName)
                $pilotesOrphelins += $orph
                continue
            }

            $signataire = 'Inconnu'
            $statutSig = 'Inconnu'
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $chemin -ErrorAction Stop
                $statutSig = [string] $sig.Status
                if ($sig.SignerCertificate) { $signataire = $sig.SignerCertificate.Subject }
            }
            catch { }

            # Un pilote n'est réputé Microsoft, et donc écarté de l'analyse, 
            # que si sa signature est VALIDE. Le Subject du certificat est
            # déclaratif : un pilote auto-signé ou à signature invalide peut y
            # inscrire « O=Microsoft Corporation ». Sans la garde sur le statut,
            # un tel pilote sortirait de l'analyse AVANT les contrôles de
            # signature et de correspondance LOLDrivers, exactement la ruse
            # que cet axe anti-BYOVD est censé attraper.
            #
            # Un pilote TIERS signé WHQL ou par attestation porte le sujet
            # « CN=Microsoft Windows Hardware Compatibility Publisher,
            #   O=Microsoft Corporation » : Microsoft le contresigne, il ne
            # l'édite pas. L'écarter retirerait de l'analyse la classe exacte
            # que le BYOVD exploite, signée, valide, acceptée par le DSE. Sur
            # un poste de test, 33 pilotes en exécution étaient dans ce cas et
            # l'inventaire n'en rapportait qu'un seul. Seul le signataire de
            # l'éditeur du système est donc écarté.
            $estMicrosoft = ($statutSig -eq 'Valid' -and
                             $signataire -match 'O=Microsoft Corporation|O=Microsoft Windows' -and
                             $signataire -notmatch 'Hardware Compatibility Publisher')
            if ($estMicrosoft) { continue }

            # Trois algorithmes calculés : la liste consolidée référence
            # certains pilotes uniquement en MD5 ou en SHA1.
            $empreinte = ''
            $empreintes = @()
            $algosCalcul = @('SHA256')
            if ($lolStructure) { $algosCalcul = @('SHA256', 'SHA1', 'MD5') }
            foreach ($al in $algosCalcul) {
                try {
                    $h = (Get-FileHash -LiteralPath $chemin -Algorithm $al -ErrorAction Stop).Hash.ToLower()
                    $empreintes += $h
                    if ($al -eq 'SHA256') { $empreinte = $h }
                }
                catch { }
            }

            $o = New-Object PSObject
            Add-Member -InputObject $o -MemberType NoteProperty -Name Nom -Value $drv.Name
            Add-Member -InputObject $o -MemberType NoteProperty -Name Chemin -Value $chemin
            Add-Member -InputObject $o -MemberType NoteProperty -Name Signataire -Value $signataire
            Add-Member -InputObject $o -MemberType NoteProperty -Name StatutSignature -Value $statutSig
            Add-Member -InputObject $o -MemberType NoteProperty -Name SHA256 -Value $empreinte
            Add-Member -InputObject $o -MemberType NoteProperty -Name Annotation -Value ''
            $pilotesTiers += $o

            if ($statutSig -ne 'Valid') { $pilotesNonSignes += $o }

            if ($lolCharge) {
                foreach ($h in $empreintes) {
                    if ($h -ne '' -and $lolIndex.ContainsKey($h)) {
                        $o.Annotation = $lolIndex[$h]
                        $pilotesVulnerables += $o
                        break
                    }
                }
            }
        }
        Write-Progress -Activity 'Analyse des pilotes noyau' -Completed

        Add-Finding 'Anti-BYOVD' 'Inventaire des pilotes noyau tiers' $ST_INFO $CR_INFO ($pilotesTiers.Count.ToString() + ' pilote(s) noyau tiers en exécution sur ' + $drivers.Count + ' pilote(s) enregistrés au total.') 'Chaque pilote tiers est une surface d''attaque potentielle. Limite de cet inventaire : il repose sur les pilotes enregistrés comme services. Un pilote chargé par mappage manuel, ou dont la clé de service a été supprimée après chargement, n''y figure pas. Les empreintes sont calculées sur le fichier disque, non sur l''image en mémoire.'

        if ($pilotesOrphelins.Count -gt 0) {
            Add-Finding 'Anti-BYOVD' 'Pilotes en exécution sans fichier sur disque' $ST_KO $CR_CRIT ($pilotesOrphelins.Count.ToString() + ' pilote(s) noyau en exécution dont le binaire est introuvable : ' + (($pilotesOrphelins | ForEach-Object { $_.Nom + ' -> ' + $_.Chemin }) -join ' ; ')) 'Constatation prioritaire. Un pilote chargé dont le fichier a été supprimé correspond au mode opératoire BYOVD : dépôt, chargement, exploitation, effacement des traces. Certains cas sont bénins (chemin non résolu, volume chiffré non monté) mais chacun doit être justifié individuellement avant clôture.'
        }
        else {
            Add-Finding 'Anti-BYOVD' 'Pilotes en exécution sans fichier sur disque' $ST_OK $CR_CRIT 'Chaque pilote noyau en exécution dispose de son binaire sur le disque.' 'Aucune action.'
        }

        if ($pilotesNonSignes.Count -gt 0) {
            Add-Finding 'Anti-BYOVD' 'Pilotes à signature non valide' $ST_KO $CR_ELEV ($pilotesNonSignes.Count.ToString() + ' pilote(s) dont la signature n''est pas valide : ' + (($pilotesNonSignes | ForEach-Object { $_.Nom }) -join ', ')) 'Vérifier l''origine de chaque pilote. Une signature invalide sur un pilote en exécution justifie une investigation.'
        }
        else {
            Add-Finding 'Anti-BYOVD' 'Pilotes à signature non valide' $ST_OK $CR_ELEV 'Tous les pilotes tiers en exécution présentent une signature valide.' 'Aucune action.'
        }

        if (-not $lolCharge) {
            Add-Finding 'Anti-BYOVD' 'Correspondance avec les pilotes vulnérables connus' $ST_UNK $CR_CRIT 'Aucune liste d''empreintes trouvée : la comparaison n''a pas été effectuée.' 'Placer le fichier AGILLY_LOLDrivers_Empreintes.csv à côté du script, ou renseigner la variable $LolDriversPath. C''est le contrôle le plus proche de la menace décrite : il détecte les pilotes vulnérables DÉJÀ présents sur le système, que ni la règle ASR ni la liste de blocage Microsoft ne couvrent.'
        }
        elseif ($pilotesVulnerables.Count -gt 0) {
            $detailVuln = @()
            foreach ($pv in $pilotesVulnerables) {
                $ligneVuln = $pv.Nom + ' (' + $pv.Chemin + ')'
                if ($pv.Annotation -ne '') { $ligneVuln += ' [' + $pv.Annotation + ']' }
                $detailVuln += $ligneVuln
            }
            $nbHvci = @($pilotesVulnerables | Where-Object { $_.Annotation -match 'malgré HVCI' }).Count
            $recoVuln = 'Constatation prioritaire : un pilote vulnérable connu est chargé sur ce système. Identifier le logiciel propriétaire, le désinstaller ou le mettre à jour, puis vérifier l''historique de chargement.'
            if ($nbHvci -gt 0) {
                $recoVuln += ' ' + $nbHvci + ' de ces pilotes se charge(nt) malgré HVCI actif : l''intégrité du code noyau ne constitue pas une contre-mesure suffisante ici, une politique App Control / WDAC sur les pilotes est nécessaire.'
            }
            Add-Finding 'Anti-BYOVD' 'Correspondance avec les pilotes vulnérables connus' $ST_KO $CR_CRIT ($pilotesVulnerables.Count.ToString() + ' pilote(s) correspondant à la liste : ' + ($detailVuln -join ' ; ')) $recoVuln
        }
        else {
            Add-Finding 'Anti-BYOVD' 'Correspondance avec les pilotes vulnérables connus' $ST_OK $CR_CRIT ('Aucune correspondance sur ' + $pilotesTiers.Count + ' pilote(s) tiers, liste de ' + $lolIndex.Count + ' empreinte(s) (' + $lolSource + ', ' + $(if ($lolShaVerifie) { 'empreinte vérifiée' } else { 'empreinte non vérifiée' }) + ').') 'La couverture dépend de la fraîcheur de la liste. Actualiser le fichier d''empreintes chaque trimestre depuis le référentiel LOLDrivers. Une empreinte non vérifiée signifie qu''aucun fichier .sha256 n''accompagnait la liste : la comparaison reste valable, mais rien n''atteste que la liste est bien celle publiée.'
        }
    }
    catch {
        Add-Erreur 'Win32_SystemDriver' $_.Exception.Message
        Add-Finding 'Anti-BYOVD' 'Inventaire des pilotes noyau tiers' $ST_UNK $CR_CRIT ('Énumération impossible. Détail : ' + $_.Exception.Message) 'Relancer en session administrateur.'
    }
}
else {
    Add-Finding 'Anti-BYOVD' 'Inventaire des pilotes noyau tiers' $ST_UNK $CR_CRIT 'Inventaire désactivé dans le paramétrage du script.' 'Positionner $ScanDrivers à $true pour activer ce contrôle.'
}

# --- Inventaire des minifiltres (Filter Manager) ---------------------------
# Win32_SystemDriver liste les pilotes enregistrés comme services, mais ne
# rend pas l'état d'attache des minifiltres ni leur altitude. Or beaucoup
# d'agents EDR opèrent en minifiltre, et « fltmc unload » décharge un
# minifiltre SANS passer par le gestionnaire de services : cette action
# échappe aux événements 7031/7034/7036/7040 déjà surveillés. On inventorie
# donc les minifiltres présents, et on croise ceux qui ne figurent pas déjà
# dans l'inventaire de service avec la liste LOLDrivers.
# Gated par $ScanDrivers, comme l'inventaire des pilotes, pour que le
# paramètre fasse ce qu'il annonce.
if ($ScanDrivers) {
    if (-not $isAdmin) {
        Add-Finding 'Anti-BYOVD' 'Inventaire des minifiltres (Filter Manager)' $ST_UNK $CR_INFO 'Énumération des minifiltres indisponible en session non élevée.' 'Relancer en session administrateur.'
        # Le contrôle de correspondance doit paraître au rapport même lorsqu'il
        # n'a pas pu s'exécuter. Le taire ferait varier le référentiel d'une
        # exécution à l'autre : le lecteur verrait un dénominateur différent sans
        # pouvoir savoir qu'un contrôle a été escamoté, et le taux de couverture
        # cesserait d'être comparable entre deux machines.
        Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_UNK $CR_ELEV 'Non évaluable : l''énumération des minifiltres exige une session élevée.' 'Relancer en session administrateur.'
    }
    else {
        try {
            # Chemin absolu : sur un PATH minimaliste (tâche planifiée, agent
            # RMM), fltmc.exe pourrait ne pas être résolu. Sous processus 32
            # bits, System32 est redirigé : on passe par Sysnative.
            $fltExe = Join-Path $env:SystemRoot 'System32\fltmc.exe'
            if ($processus32SurOs64) { $fltExe = Join-Path $env:SystemRoot 'Sysnative\fltmc.exe' }
            $fltSortie = '' | & $fltExe filters 2>$null

            $minifiltresNoms = @()
            $minifiltresAff = @()
            foreach ($ligne in $fltSortie) {
                if ($ligne -match '^(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s*$') {
                    $nomF = $matches[1].Trim()
                    $minifiltresNoms += $nomF
                    $minifiltresAff += ($nomF + ' (alt. ' + $matches[3] + ')')
                }
            }

            if ($minifiltresNoms.Count -gt 0) {
                Add-Finding 'Anti-BYOVD' 'Inventaire des minifiltres (Filter Manager)' $ST_INFO $CR_INFO ($minifiltresNoms.Count.ToString() + ' minifiltre(s) chargé(s) : ' + ($minifiltresAff -join ', ') + '.') 'Confirmer que le minifiltre de l''agent de sécurité figure dans la liste. Rappel : « fltmc unload » peut décharger un minifiltre sans arrêt de service et sans événement 7036/7040, surveiller les déchargements côté agent. Un déchargement inattendu du minifiltre EDR est un signal d''évasion.'
            }
            else {
                Add-Finding 'Anti-BYOVD' 'Inventaire des minifiltres (Filter Manager)' $ST_UNK $CR_INFO 'Aucun minifiltre lisible via fltmc, ou sortie non exploitable.' 'Vérifier manuellement avec « fltmc filters ». Une absence totale de minifiltre sur un poste doté d''un EDR moderne est anormale.'
            }

            # --- Croisement minifiltres non inventoriés x LOLDrivers ---
            # Un minifiltre enregistré comme service est déjà couvert par la
            # boucle Win32_SystemDriver. On ne traite ici que ceux qui n'y
            # figurent pas, pour ne pas compter deux fois. Le hachage suppose
            # une résolution de chemin fiable : neutralisé sous WOW64.
            if ((-not $processus32SurOs64) -and $lolCharge -and $minifiltresNoms.Count -gt 0) {
                $dejaVus = @{}
                foreach ($pt in $pilotesTiers) { $dejaVus[$pt.Nom.ToLower()] = $true }
                $mfVulnerables = @()
                $mfOrphelins = @()
                $mfExamines = 0
                foreach ($nomF in $minifiltresNoms) {
                    if ($dejaVus.ContainsKey($nomF.ToLower())) { continue }
                    $imgPath = Get-RegValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $nomF) -Name 'ImagePath'
                    if (-not $imgPath.Found) { continue }
                    $cheminF = Resolve-DriverPath ([string] $imgPath.Value)
                    if (-not $cheminF) { continue }
                    $mfExamines++
                    if (-not (Test-Path -LiteralPath $cheminF -ErrorAction SilentlyContinue)) {
                        $mfOrphelins += ($nomF + ' -> ' + $cheminF)
                        continue
                    }
                    $algosF = @('SHA256'); if ($lolStructure) { $algosF = @('SHA256', 'SHA1', 'MD5') }
                    foreach ($al in $algosF) {
                        try {
                            $hF = (Get-FileHash -LiteralPath $cheminF -Algorithm $al -ErrorAction Stop).Hash.ToLower()
                            if ($hF -ne '' -and $lolIndex.ContainsKey($hF)) {
                                $annotF = $lolIndex[$hF]
                                $mfVulnerables += ($nomF + ($(if ($annotF) { ' (' + $annotF + ')' } else { '' })))
                                break
                            }
                        }
                        catch { }
                    }
                }
                if ($mfVulnerables.Count -gt 0) {
                    Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_KO $CR_CRIT ($mfVulnerables.Count.ToString() + ' minifiltre(s) correspondant à la liste des pilotes vulnérables : ' + ($mfVulnerables -join ' ; ') + '.') 'Un minifiltre vulnérable chargé est un vecteur BYOVD actif. Identifier l''origine et retirer le pilote ; compléter par une politique WDAC par signataire.'
                }
                if ($mfOrphelins.Count -gt 0) {
                    Add-Finding 'Anti-BYOVD' 'Minifiltres en exécution sans fichier sur disque' $ST_KO $CR_CRIT ($mfOrphelins.Count.ToString() + ' minifiltre(s) chargé(s) dont le binaire est introuvable : ' + ($mfOrphelins -join ' ; ') + '.') 'Un minifiltre en exécution sans fichier sur disque correspond au mode opératoire BYOVD. Investiguer chaque cas.'
                }
                if ($mfVulnerables.Count -eq 0 -and $mfOrphelins.Count -eq 0 -and $mfExamines -gt 0) {
                    Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_OK $CR_ELEV ('Aucune correspondance sur ' + $mfExamines + ' minifiltre(s) non déjà inventorié(s).') 'Aucune action.'
                }
                elseif ($mfExamines -eq 0) {
                    Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_INFO $CR_INFO 'Tous les minifiltres chargés figurent déjà dans l''inventaire des pilotes de service et y ont été comparés à la liste. Situation normale.' 'Aucune action ; ce constat confirme l''absence d''angle mort, pas un oubli de contrôle.'
                }
            }
            else {
                # Même exigence : liste d'empreintes absente, processus 32 bits
                # ou aucun minifiltre lu, le contrôle sort INDÉTERMINÉ, il ne
                # disparaît pas du rapport.
                $motifMf = 'conditions d''exécution insuffisantes'
                if ($processus32SurOs64) { $motifMf = 'processus 32 bits sur OS 64 bits : la résolution des chemins de pilotes n''est pas fiable' }
                elseif (-not $lolCharge) { $motifMf = 'référentiel d''empreintes non chargé' }
                elseif ($minifiltresNoms.Count -eq 0) { $motifMf = 'aucun minifiltre lisible' }
                Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_UNK $CR_ELEV ('Non évaluable : ' + $motifMf + '.') 'Relancer avec le référentiel d''empreintes présent à côté du script, dans une console 64 bits élevée.'
            }
        }
        catch {
            Add-Finding 'Anti-BYOVD' 'Inventaire des minifiltres (Filter Manager)' $ST_UNK $CR_INFO ('Exécution de fltmc impossible. Détail : ' + $_.Exception.Message) 'Vérifier manuellement avec « fltmc filters » en session administrateur.'
            Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_UNK $CR_ELEV 'Non évaluable : l''énumération des minifiltres a échoué.' 'Vérifier manuellement avec « fltmc filters » en session administrateur.'
        }
    }
}
else {
    Add-Finding 'Anti-BYOVD' 'Inventaire des minifiltres (Filter Manager)' $ST_UNK $CR_INFO 'Inventaire désactivé par paramètre (-ScanDrivers:$false).' 'Relancer sans désactiver l''inventaire des pilotes.'
    Add-Finding 'Anti-BYOVD' 'Minifiltres vulnérables (hors inventaire de service)' $ST_UNK $CR_ELEV 'Non évaluable : inventaire désactivé par paramètre (-ScanDrivers:$false).' 'Relancer sans désactiver l''inventaire des pilotes.'
}


# ===========================================================================
#  SCORE ET SYNTHÈSE
# ===========================================================================

$evalues = @($findings | Where-Object { $_.Etat -eq $ST_OK -or $_.Etat -eq $ST_PRES -or $_.Etat -eq $ST_KO -or $_.Etat -eq $ST_CONF })
$ptsObtenus = 0
$ptsTotal = 0
foreach ($f in $evalues) {
    $p = 0
    if ($POIDS.ContainsKey($f.Criticite)) { $p = $POIDS[$f.Criticite] }
    $ptsTotal += $p
    if ($f.Etat -eq $ST_OK) { $ptsObtenus += $p }
    if ($f.Etat -eq $ST_PRES) { $ptsObtenus += [math]::Round($p * 0.7) }
}

$score = 0
if ($ptsTotal -gt 0) { $score = [int] [math]::Round(($ptsObtenus / $ptsTotal) * 100) }

$nbOk   = @($findings | Where-Object { $_.Etat -eq $ST_OK -or $_.Etat -eq $ST_PRES }).Count
$nbKo   = @($findings | Where-Object { $_.Etat -eq $ST_KO }).Count
$nbConf = @($findings | Where-Object { $_.Etat -eq $ST_CONF }).Count
$nbUnk  = @($findings | Where-Object { $_.Etat -eq $ST_UNK }).Count
$nbNa   = @($findings | Where-Object { $_.Etat -eq $ST_NA }).Count
$nbConsole = @($findings | Where-Object { $_.Etat -eq $ST_CONSOLE }).Count
$nbTri  = @($findings | Where-Object { $_.Etat -eq $ST_TRI }).Count

$koCrit = @($findings | Where-Object { $_.Etat -eq $ST_KO -and $_.Criticite -eq $CR_CRIT }).Count
$koElev = @($findings | Where-Object { $_.Etat -eq $ST_KO -and $_.Criticite -eq $CR_ELEV }).Count

# Un ratio pondéré peut afficher 85/100 sur une machine portant un pilote
# vulnérable chargé, tandis qu'une machine à 60/100 sans écart critique est
# objectivement moins exposée. Le plafonnement empêche le score d'inverser
# la hiérarchie du risque.
$scorePlafonne = $false
if ($koCrit -gt 0 -and $score -gt 49) {
    $score = 49
    $scorePlafonne = $true
}

$maturite = 'Insuffisant'
if ($score -ge 90) { $maturite = 'Élevé' }
elseif ($score -ge 75) { $maturite = 'Satisfaisant' }
elseif ($score -ge 50) { $maturite = 'Partiel' }

$couverture = 0
# Le dénominateur reste le périmètre mesurable complet (hors INFO, NON
# APPLICABLE et À VÉRIFIER EN CONSOLE) ; seul le sous-ensemble d'INDÉTERMINÉS
# appartenant à ce périmètre est retiré du numérateur.
$mesurables = @($findings | Where-Object { $_.Criticite -ne $CR_INFO -and $_.Etat -ne $ST_NA -and $_.Etat -ne $ST_CONSOLE -and $_.Etat -ne $ST_TRI })
$totalMesurables = $mesurables.Count
$unkMesurables = @($mesurables | Where-Object { $_.Etat -eq $ST_UNK }).Count
if ($totalMesurables -gt 0) {
    $couverture = [int] [math]::Round((($totalMesurables - $unkMesurables) / $totalMesurables) * 100)
}

# Un audit incomplet (session non élevée, processus 32 bits, ou couverture
# sous le seuil) ne doit jamais être présenté comme un état sain, ni en RMM
# (code de sortie) ni dans le rapport (bandeau). Calculé ici pour être
# disponible dès la génération du rapport.
$auditNonConcluant = ((-not $isAdmin) -or $processus32SurOs64 -or ($couverture -lt $CouvertureMinimale))


# ===========================================================================
#  RESTITUTION CONSOLE
# ===========================================================================

Write-Host ''
Write-Host '--- CONTEXTE ---' -ForegroundColor Yellow
$contexte | Format-List

Write-Host '--- CONSTATS PAR CRITICITÉ ---' -ForegroundColor Yellow
Write-Host ''

$ordre = @($CR_CRIT, $CR_ELEV, $CR_MOY, $CR_FAIB, $CR_INFO)
foreach ($niveau in $ordre) {
    $lot = @($findings | Where-Object { $_.Criticite -eq $niveau })
    if ($lot.Count -eq 0) { continue }
    Write-Host ('  [ ' + $niveau.ToUpper() + ' ]') -ForegroundColor White
    foreach ($f in $lot) {
        $couleur = 'Yellow'
        if ($f.Etat -eq $ST_OK) { $couleur = 'Green' }
        if ($f.Etat -eq $ST_PRES) { $couleur = 'DarkGreen' }
        if ($f.Etat -eq $ST_KO) { $couleur = 'Red' }
        if ($f.Etat -eq $ST_CONF) { $couleur = 'DarkYellow' }
        if ($f.Etat -eq $ST_NA) { $couleur = 'DarkGray' }
        if ($f.Etat -eq $ST_INFO) { $couleur = 'Cyan' }
        if ($f.Etat -eq $ST_CONSOLE) { $couleur = 'Magenta' }
        if ($f.Etat -eq $ST_TRI) { $couleur = 'DarkCyan' }

        Write-Host ('   ' + $f.Etat.PadRight(24) + ' ' + $f.Controle) -ForegroundColor $couleur
        Write-Host ('      Constat        : ' + $f.Detail) -ForegroundColor Gray
        if ($f.Etat -eq $ST_KO -or $f.Etat -eq $ST_PRES -or $f.Etat -eq $ST_CONF -or $f.Etat -eq $ST_TRI) {
            Write-Host ('      Recommandation : ' + $f.Recommandation) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

Write-Host '--- SYNTHÈSE ---' -ForegroundColor Yellow
Write-Host ('  Score de durcissement    : ' + $score + ' / 100   (' + $maturite + ')')
if ($scorePlafonne) {
    Write-Host '                             Score plafonné à 49 : au moins un écart critique.' -ForegroundColor Red
}
Write-Host ('  Conformes                : ' + $nbOk)
Write-Host ('  Non conformes            : ' + $nbKo + '   dont ' + $koCrit + ' critique(s) et ' + $koElev + ' élevée(s)')
Write-Host ('  Configurés non actifs    : ' + $nbConf)
Write-Host ('  Indéterminés             : ' + $nbUnk)
Write-Host ('  À vérifier en console    : ' + $nbConsole)
Write-Host ('  À trier (historique)     : ' + $nbTri)
Write-Host ('  Non applicables          : ' + $nbNa)
Write-Host ('  Couverture d''audit       : ' + $couverture + ' %')
Write-Host ''

if ($processus32SurOs64) {
    Write-Warning 'Processus 32 bits : l''inventaire des pilotes noyau n''a pas été exécuté. Relancer en 64 bits.'
}

if ($nbUnk -gt 0) {
    Write-Warning ($nbUnk.ToString() + ' contrôle(s) non évalué(s). Ce n''est PAS une non-conformité.')
}
if ($erreursExecution.Count -gt 0) {
    Write-Warning ($erreursExecution.Count.ToString() + ' erreur(s) d''exécution enregistrée(s). Voir $erreursExecution.')
}

Write-Host ''
Write-Host 'Rappel de portée : ce rapport mesure le socle de durcissement.' -ForegroundColor DarkGray
Write-Host 'Il ne mesure pas la résistance réelle à une tentative d''extinction d''agent.' -ForegroundColor DarkGray
Write-Host ''


# ===========================================================================
#  EXPORT MACHINE
# ===========================================================================

if ($ExportPath -ne '') {
    try {
        $plat = $findings | Select-Object @{N='Machine';E={$contexte.Machine}}, @{N='Domaine';E={$contexte.Domaine}}, @{N='DateAudit';E={$contexte.DateAudit}}, @{N='Build';E={$contexte.Build}}, @{N='Score';E={$score}}, Axe, Controle, Technique, Criticite, Etat, Detail, Recommandation

        if ($ExportPath -match '\.json$') {
            $payload = New-Object PSObject
            Add-Member -InputObject $payload -MemberType NoteProperty -Name Contexte -Value $contexte
            Add-Member -InputObject $payload -MemberType NoteProperty -Name Score -Value $score
            Add-Member -InputObject $payload -MemberType NoteProperty -Name Maturite -Value $maturite
            Add-Member -InputObject $payload -MemberType NoteProperty -Name Couverture -Value $couverture
            Add-Member -InputObject $payload -MemberType NoteProperty -Name Constats -Value $plat
            $payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportPath -Encoding UTF8
        }
        else {
            $plat | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        }
        Write-Host ('Export écrit : ' + $ExportPath) -ForegroundColor Green
    }
    catch {
        Write-Warning ('Échec de l''export : ' + $_.Exception.Message)
    }
}


# ===========================================================================
#  RAPPORT HTML, CHARTE AGILLY
# ===========================================================================

if ($HtmlReportPath -ne '') {
    try {
        $couleurJauge = '#C0392B'
        if ($score -ge 90) { $couleurJauge = '#2E7D32' }
        elseif ($score -ge 75) { $couleurJauge = '#F58732' }
        elseif ($score -ge 50) { $couleurJauge = '#D68910' }

        $lignesCtx = ''
        foreach ($p in $contexte.PSObject.Properties) {
            $lignesCtx += '<tr><th>' + (Protect-Html $p.Name) + '</th><td>' + (Protect-Html ([string] $p.Value)) + '</td></tr>'
        }

        $lignesConstats = ''
        foreach ($niveau in $ordre) {
            $lot = @($findings | Where-Object { $_.Criticite -eq $niveau })
            if ($lot.Count -eq 0) { continue }
            $lignesConstats += '<h3 class="niv">' + (Protect-Html $niveau) + '</h3><table class="constats">'
            $lignesConstats += '<tr><th style="width:16%">État</th><th style="width:26%">Contrôle</th><th>Constat et recommandation</th></tr>'
            foreach ($f in $lot) {
                $cls = 'unk'
                if ($f.Etat -eq $ST_OK) { $cls = 'ok' }
                if ($f.Etat -eq $ST_PRES) { $cls = 'pres' }
                if ($f.Etat -eq $ST_KO) { $cls = 'ko' }
                if ($f.Etat -eq $ST_CONF) { $cls = 'conf' }
                if ($f.Etat -eq $ST_NA) { $cls = 'na' }
                if ($f.Etat -eq $ST_INFO) { $cls = 'info' }
                if ($f.Etat -eq $ST_CONSOLE) { $cls = 'console' }
                if ($f.Etat -eq $ST_TRI) { $cls = 'tri' }

                $bloc = '<div class="det">' + (Protect-Html $f.Detail) + '</div>'
                if ($f.Etat -eq $ST_KO -or $f.Etat -eq $ST_PRES -or $f.Etat -eq $ST_CONF -or $f.Etat -eq $ST_CONSOLE -or $f.Etat -eq $ST_TRI) {
                    $bloc += '<div class="rec"><strong>Recommandation.</strong> ' + (Protect-Html $f.Recommandation) + '</div>'
                }
                $sousTitre = Protect-Html $f.Axe
                if ($f.Technique -ne '') { $sousTitre += ' | ATT&amp;CK ' + (Protect-Html $f.Technique) }
                $lignesConstats += '<tr><td><span class="badge ' + $cls + '">' + (Protect-Html $f.Etat) + '</span></td><td class="ctrl">' + (Protect-Html $f.Controle) + '<div class="axe">' + $sousTitre + '</div></td><td>' + $bloc + '</td></tr>'
            }
            $lignesConstats += '</table>'
        }

        # --- Familles de contrôles (intro technique) ---
        # Construite depuis les constats réels : reste juste quelle que soit
        # l'évolution des contrôles. Un descripteur court par famille.
        $famDescr = [ordered]@{
            'Socle firmware'        = 'Secure Boot, options de démarrage du noyau'
            'Intégrité noyau'       = 'VBS, HVCI, Credential Guard, protection LSA et DMA'
            'Anti-BYOVD'            = 'WDAC, liste de blocage, règle ASR pilotes, pilotes tiers et minifiltres, correspondance LOLDrivers'
            'Intégrité de l''agent' = 'détection multi-éditeurs, état des services, anti-sabotage, mode sans échec, fraîcheur des signatures'
            'Télémétrie'            = 'rattachement à la console, journalisation PowerShell et AMSI, exclusions, rétention des journaux'
            'Réduction de surface'  = 'posture des règles ASR (règles clés et prévalence)'
            'Historique'            = 'arrêts et plantages de services, installation de pilotes, effacement de journaux, collecteur indépendant'
            'Privilèges'            = 'administrateurs locaux, LAPS, UAC'
        }
        $lignesFamilles = ''
        foreach ($fam in $famDescr.Keys) {
            $n = @($findings | Where-Object { $_.Axe -eq $fam }).Count
            if ($n -eq 0) { continue }
            $lignesFamilles += '<tr><td class="ctrl" style="width:24%">' + (Protect-Html $fam) + '</td><td style="width:8%;color:#888">' + $n + '</td><td>' + (Protect-Html $famDescr[$fam]) + '</td></tr>'
        }

        $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8" />
<title>AGILLY Cyberdéfense - Audit du socle - $(Protect-Html $contexte.Machine)</title>
<style>
  :root { --orange:#F58732; --anthracite:#191919; }
  * { box-sizing:border-box; }
  body { font-family:'Eurostyle','Eurostile','Square721 BT','Arial Narrow',Arial,sans-serif;
         color:var(--anthracite); background:#F4F4F4; margin:0; padding:0 0 48px 0; font-size:14px; }
  header { background:var(--anthracite); color:#FFF; padding:26px 40px; border-bottom:4px solid var(--orange); }
  header .marque { font-size:22px; letter-spacing:2px; text-transform:uppercase; }
  header .marque span { color:var(--orange); }
  header .titre { font-size:15px; color:#BDBDBD; margin-top:6px; }
  main { max-width:1080px; margin:28px auto; padding:0 20px; }
  .carte { background:#FFF; border:1px solid #E0E0E0; padding:22px 26px; margin-bottom:22px; }
  h2 { font-size:16px; text-transform:uppercase; letter-spacing:1px; border-left:4px solid var(--orange);
       padding-left:10px; margin:0 0 16px 0; }
  h3.niv { font-size:13px; text-transform:uppercase; letter-spacing:1.5px; color:#555;
           margin:22px 0 8px 0; padding-bottom:4px; border-bottom:1px solid #E0E0E0; }
  table { border-collapse:collapse; width:100%; }
  th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid #EEE; font-size:13px; }
  th { color:#555; font-weight:normal; text-transform:uppercase; font-size:11px; letter-spacing:1px; }
  .ctx th { width:180px; }
  .ctrl { font-weight:bold; }
  .axe { font-weight:normal; color:#888; font-size:11px; margin-top:3px; }
  .det { margin-bottom:5px; }
  .rec { color:#444; border-left:2px solid var(--orange); padding-left:9px; font-size:12px; }
  .badge { display:inline-block; padding:3px 8px; font-size:10px; letter-spacing:.5px;
           text-transform:uppercase; color:#FFF; white-space:nowrap; }
  .badge.ok{background:#2E7D32}.badge.pres{background:#7CB342}.badge.ko{background:#C0392B}
  .badge.conf{background:#E67E22}.badge.unk{background:#D68910}.badge.na{background:#9E9E9E}.badge.info{background:#37474F}.badge.console{background:#6C3FA0}.badge.tri{background:#00695C}
  .score { display:flex; align-items:center; gap:26px; flex-wrap:wrap; }
  .score .val { font-size:52px; font-weight:bold; color:$couleurJauge; line-height:1; }
  .score .lbl { font-size:12px; text-transform:uppercase; letter-spacing:1.5px; color:#666; }
  .jauge { flex:1; min-width:240px; height:14px; background:#E0E0E0; }
  .jauge div { height:14px; width:$score%; background:$couleurJauge; }
  .chiffres { display:flex; gap:32px; margin-top:18px; flex-wrap:wrap; }
  .chiffres div span { display:block; font-size:24px; font-weight:bold; }
  .chiffres div small { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#666; }
  .avert { background:#FFF6EE; border-left:4px solid var(--orange); padding:14px 18px; font-size:13px; }
  footer { max-width:1080px; margin:0 auto; padding:0 20px; color:#888; font-size:11px; line-height:1.6; }
  @page { size:A4; margin:12mm 10mm; }
  @media print {
    body { background:#FFF; font-size:10.5pt; }
    header { padding:16px 20px; }
    main { margin:14px auto; padding:0; max-width:100%; }
    .carte { border:1px solid #CCC; padding:14px 16px; margin-bottom:14px; page-break-inside:avoid; }
    h3.niv { page-break-after:avoid; }
    table.constats tr { page-break-inside:avoid; }
    .badge { border:1px solid #666; }
    a { text-decoration:none; color:inherit; }
  }
</style>
</head>
<body>
<header>
  <div class="marque">agil<span>ly</span> &nbsp;Cyberdéfense</div>
  <div class="titre">Audit du socle Windows face aux vecteurs d'évasion EDR, version $VERSION_SCRIPT</div>
</header>
<main>

  <div class="carte">
    <strong>Objet.</strong> Cet audit mesure le durcissement du poste face aux conditions préalables
    qu'exploitent les techniques de neutralisation d'agent EDR : privilèges locaux, chargement de
    pilote noyau, absence de politique d'intégrité du code, arrêt de service, absence de télémétrie
    transmise à un tiers. Chaque condition retirée renchérit l'attaque et augmente sa probabilité de
    détection.
    <table class="ctx" style="margin-top:14px">
      <tr><th style="width:24%">Famille</th><th style="width:8%">Contrôles</th><th>Périmètre</th></tr>
      $lignesFamilles
    </table>
    <p style="margin:14px 0 0 0;font-size:12px;color:#666;">
      <strong>Portée.</strong> Un socle conforme ne garantit pas qu'un agent résisterait à une attaque
      ciblée, la résistance effective relève d'un test contrôlé, distinct de cet audit. Chaque contrôle
      lit l'état de la machine par les interfaces que Windows lui-même expose : les verdicts sont valides
      sous hypothèse d'un système non compromis. Cela vaut aussi pour les contrôles d'intégrité noyau,
      dont l'état est rapporté à travers le noyau qu'ils décrivent.
    </p>
    <p style="margin:8px 0 0 0;font-size:12px;color:#666;">
      <strong>Lecture ATT&amp;CK.</strong> Les identifiants portés par chaque contrôle désignent la
      technique que ce contrôle contraint ou dont il détecte la trace. Ils qualifient le contrôle, non
      la machine : ils ne signifient pas que la technique a été observée ici.
    </p>
  </div>

  <div class="carte">
    <h2>Score de durcissement</h2>
    <div class="score">
      <div><div class="val">$score</div><div class="lbl">sur 100, $maturite$(if ($scorePlafonne) { ', score plafonné' })</div></div>
      <div class="jauge"><div></div></div>
    </div>
    <div class="chiffres">
      <div><span>$nbOk</span><small>Conformes</small></div>
      <div><span>$nbKo</span><small>Non conformes</small></div>
      <div><span>$nbConf</span><small>Configurés non actifs</small></div>
      <div><span>$koCrit</span><small>Écarts critiques</small></div>
      <div><span>$nbUnk</span><small>Indéterminés</small></div>
      <div><span>$nbConsole</span><small>À vérifier en console</small></div>
      <div><span>$nbTri</span><small>À trier (historique)</small></div>
      <div><span>$couverture&nbsp;%</span><small>Couverture d'audit</small></div>
    </div>
    $(if ($nbTri -gt 0) { '<p style="margin:14px 0 0 0;font-size:12px;color:#00695C;"><strong>' + $nbTri + ' signal(aux) d''historique à trier.</strong> Ces constats relèvent d''événements journalisés, dont l''interprétation exige une corrélation avec les fenêtres de maintenance et le cycle de mise à jour des agents, informations dont l''audit ne dispose pas. Ils ne pèsent ni sur le score ni sur la couverture, et doivent être lus séparément.</p>' })
    $(if ($scorePlafonne) { '<p style="margin:14px 0 0 0;font-size:12px;color:#C0392B;"><strong>Score plafonné à 49.</strong> Au moins un écart de criticité critique a été relevé : aucune machine portant un tel écart ne peut être présentée comme satisfaisante, quel que soit le nombre de contrôles conformes par ailleurs.</p>' })
    $(if ($auditNonConcluant) { '<p style="margin:14px 0 0 0;font-size:12px;color:#6C3FA0;"><strong>Audit non concluant.</strong> Les conditions d''exécution (session non élevée, processus 32 bits, ou couverture insuffisante) ne permettent pas de conclure : l''absence d''écart relevé ne vaut pas conformité. Relancer dans de bonnes conditions avant toute restitution.</p>' })
  </div>

  <div class="carte">
    <h2>Contexte du système audité</h2>
    <table class="ctx">$lignesCtx</table>
  </div>

  <div class="carte">
    <h2>Constats détaillés</h2>
    $lignesConstats
  </div>

</main>
<footer>
  AGILLY Cyberdéfense, Expertise, Détection &amp; Architecture de Résilience, infos@agilly.net, www.agilly.net<br />
  Rapport généré le $(Protect-Html $contexte.DateAudit) par le script d'audit version $VERSION_SCRIPT, en lecture seule et sans transmission réseau.<br />
  Verdicts : CONFORME | CONFORME (PRÉSUMÉ) | NON CONFORME | CONFIGURÉ (NON ACTIF) | INDÉTERMINÉ (non mesuré, pas une non-conformité) | NON APPLICABLE | À VÉRIFIER EN CONSOLE | À TRIER (signal d'historique à corréler) | INFORMATION.<br />
  Document destiné au destinataire de l'audit.
</footer>
</body>
</html>
"@

        [System.IO.File]::WriteAllText($HtmlReportPath, $html, (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ('Rapport HTML écrit : ' + $HtmlReportPath) -ForegroundColor Green
    }
    catch {
        Write-Warning ('Échec de génération du rapport HTML : ' + $_.Exception.Message)
    }
}


# ===========================================================================
#  RÉCAPITULATIF DES LIVRABLES
# ===========================================================================

$fichiersGeneres = @()
if ($HtmlReportPath -ne '' -and (Test-Path -LiteralPath $HtmlReportPath)) { $fichiersGeneres += $HtmlReportPath }
if ($ExportPath -ne '' -and (Test-Path -LiteralPath $ExportPath)) { $fichiersGeneres += $ExportPath }

Write-Host ''
Write-Host '--- LIVRABLES ---' -ForegroundColor Yellow
if ($fichiersGeneres.Count -eq 0) {
    Write-Warning 'Aucun livrable généré. Vérifier les avertissements ci-dessus.'
}
else {
    Write-Host ('  Dossier : ' + $dossierRetenu) -ForegroundColor Green
    foreach ($f in $fichiersGeneres) {
        $taille = 0
        try { $taille = [math]::Round((Get-Item -LiteralPath $f).Length / 1KB, 1) } catch { }
        Write-Host ('   - ' + (Split-Path -Leaf $f) + '   (' + $taille + ' Ko)') -ForegroundColor Green
    }
    Write-Host ''
    Write-Host '  Ouvrir le dossier :' -ForegroundColor DarkGray
    Write-Host ('    explorer.exe "' + $dossierRetenu + '"') -ForegroundColor DarkGray
    if ($HtmlReportPath -ne '') {
        Write-Host '  Ouvrir le rapport :' -ForegroundColor DarkGray
        Write-Host ('    Start-Process "' + $HtmlReportPath + '"') -ForegroundColor DarkGray
        Write-Host '  Puis Ctrl+P dans le navigateur pour un PDF.' -ForegroundColor DarkGray
    }
}
Write-Host ''

if ($OuvrirRapport -and $fichiersGeneres.Count -gt 0) {
    try { Start-Process -FilePath $fichiersGeneres[0] | Out-Null }
    catch { Write-Warning ('Ouverture automatique impossible : ' + $_.Exception.Message) }
}


# ===========================================================================
#  CODE DE SORTIE
# ===========================================================================

# Priorité : une erreur totale prime, puis les écarts par gravité, puis le
# caractère non concluant. Le point clé : un audit incomplet (session non
# élevée, processus 32 bits, ou couverture sous le seuil) ne doit JAMAIS
# renvoyer 0 « aucun écart » en RMM, ce serait un faux vert sur tout un parc.
# $auditNonConcluant est calculé plus haut, avant la génération du rapport.

$codeSortie = 0
if ($erreursExecution.Count -gt 0 -and $nbOk -eq 0) { $codeSortie = 5 }
elseif ($koCrit -gt 0) { $codeSortie = 3 }
elseif ($koElev -gt 0) { $codeSortie = 2 }
elseif ($nbKo -gt 0) { $codeSortie = 1 }
elseif ($auditNonConcluant) { $codeSortie = 4 }

if ($codeSortie -eq 4) {
    $raisons = @()
    if (-not $isAdmin)           { $raisons += 'session non élevée' }
    if ($processus32SurOs64)     { $raisons += 'processus 32 bits sur OS 64 bits' }
    if ($couverture -lt $CouvertureMinimale) { $raisons += 'couverture ' + $couverture + '% < ' + $CouvertureMinimale + '%' }
    Write-Warning ('Audit NON CONCLUANT (' + ($raisons -join ', ') + ') : l''absence d''écart ne vaut pas conformité. Relancer dans de bonnes conditions.')
}

if ($estFichier) {
    exit $codeSortie
}
else {
    Write-Host ('Code de sortie calculé : ' + $codeSortie + ' (non propagé en mode console)') -ForegroundColor DarkGray
}
