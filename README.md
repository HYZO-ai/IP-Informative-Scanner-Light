# IP Informative Scanner Light

**IP Informative Scanner Light** est un script PowerShell conçu pour collecter rapidement des informations réseau et de sécurité sur une machine distante (ou locale), à partir de son adresse IP ou de son nom d'hôte. Il fournit une vue d'ensemble utile pour les diagnostics, audits internes ou phases de reconnaissance autorisées.

---

## Fonctionnalités

Le script effectue les actions suivantes :

### Informations générales

- Détection du type d’adresse IP (Privée, Publique, Loopback)

### Diagnostic réseau

- Ping détaillé (paquets envoyés/reçus/perdus, moyenne de latence)
- Détection de blocage ICMP
- Test de fragmentation ICMP (`Don't Fragment`)
- Traceroute condensé : liste des sauts IP uniquement (sans latence ni détails inutiles)

### Analyse de ports

- Scan rapide des ports les plus courants :
  - FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53)
  - HTTP (80), HTTPS (443), SMB (445), RDP (3389), etc.
- Identification des services accessibles sur les ports ouverts

### Tests de sécurité réseau

- Test d’accessibilité RDP
- Vérification du serveur HTTP et analyse de la bannière (détection de versions obsolètes connues)
- Test d'accès FTP anonyme
- Vérification de l’état local de SMBv1
- Test de service Telnet

---

## Prérequis

- **Système** : Windows 10 / 11 ou Windows Server
- **PowerShell** : Version 5.1 ou supérieure
- **Permissions** : Élevées recommandées (exécution en tant qu'administrateur)
- **Connexion réseau** : Active pour les tests sur IP distantes

Aucun module externe n'est requis. Le script repose uniquement sur des commandes intégrées à PowerShell (`Test-Connection`, `Test-NetConnection`, `Invoke-WebRequest`, etc.).

---

## Utilisation

1. Ouvrez PowerShell en tant qu’administrateur.

2. Exécutez le script :

    ```powershell
    .\ip-informative-scanner-light.ps1
    ```

3. Entrez l’adresse IP ou le nom d’hôte à analyser lorsqu’il vous est demandé.

---

## Exemple de sortie

```text
========== RAPPORT RÉSEAU POUR : 192.168.1.1 ==========
Type d'adresse        : Privée
Ping                  : Répond (4/4 reçus, 0 perdus) - Moyenne: 2.4 ms
ICMP global           : ICMP accessible
Test fragmentation ICMP : OK
Traceroute            : 192.168.1.1 → 10.0.0.1 → 8.8.8.8

Scan de ports         :
80 ouvert (HTTP)
443 ouvert (HTTPS)
3389 ouvert (RDP)

Tests de sécurité     :
  RDP actif (port 3389 ouvert)
  HTTP 200 OK - Serveur : nginx/1.4 (version ancienne détectée)
  FTP anonyme refusé
  SMBv1 désactivé
  Telnet non accessible

========== FIN DU RAPPORT ==========
