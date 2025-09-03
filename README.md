# ft_nmap

Un scanner réseau écrit en C inspiré de Nmap.  
Il supporte plusieurs types de scans TCP/UDP et affiche l’état des ports selon les réponses reçues.

---

## 🚀 Fonctionnalités

- Détection d’hôtes et de ports ouverts/fermés/filtrés
- Support de plusieurs types de scans TCP (`SYN`, `FIN`, `NULL`, `XMAS`, `ACK`)
- Scan UDP avec interprétation des réponses ICMP
- Multi-threading pour accélérer les envois
- Capture des paquets via `libpcap`

---

## 🔍 Types de scans supportés

### 🔹 **SYN Scan** (`--scan SYN`) — *le plus courant*
- **Principe** : envoie un paquet TCP avec le flag `SYN`.  
  Si la cible répond `SYN/ACK` → **OPEN**. Si elle répond `RST` → **CLOSED**.
- **Avantage** : rapide et efficace. Ne complète pas la connexion TCP (semi-ouvert), ce qui le rend discret.
- **Quand l’utiliser** : c’est généralement le choix par défaut pour une cartographie rapide.

---

### 🔹 **FIN Scan** (`--scan FIN`)
- **Principe** : envoie un paquet TCP avec le flag `FIN`.  
  Selon la RFC, un port fermé doit répondre par `RST`. Si aucun paquet ne revient → **OPEN|FILTERED**.
- **Avantage** : peut contourner certains pare-feu ou systèmes qui logguent uniquement les `SYN`.
- **Quand l’utiliser** : utile contre des IDS/pare-feu trop basiques.

---

### 🔹 **NULL Scan** (`--scan NULL`)
- **Principe** : envoie un paquet TCP sans aucun flag activé.  
  Même logique que le `FIN` → `RST` = **CLOSED**, aucune réponse = **OPEN|FILTERED**.
- **Avantage** : comportement étrange pour beaucoup de stacks réseau, ce qui peut révéler des infos.
- **Quand l’utiliser** : test complémentaire au `FIN`, utile pour contourner certains systèmes de détection.

---

### 🔹 **XMAS Scan** (`--scan XMAS`)
- **Principe** : envoie un paquet TCP avec les flags `FIN+PSH+URG`.  
  Même logique que `FIN` et `NULL`.
- **Origine du nom 🎄** : le paquet est “illuminé” de plusieurs flags, comme un sapin de Noël allumé.  
- **Quand l’utiliser** : technique d’évasion, peut donner des résultats différents selon l’OS.

---

### 🔹 **ACK Scan** (`--scan ACK`)
- **Principe** : envoie un paquet TCP avec le flag `ACK`.  
  Ne permet pas de savoir si le port est ouvert, mais si la cible répond → **UNFILTERED**, sinon **FILTERED**.
- **Avantage** : permet de cartographier les règles de pare-feu.
- **Quand l’utiliser** : pour détecter la présence de filtres sans s’intéresser à l’état des services.

---

### 🔹 **UDP Scan** (`--scan UDP`)
- **Principe** : envoie un paquet UDP sur un port.  
  - Réponse ICMP “Port Unreachable” → **CLOSED**  
  - Réponse UDP → **OPEN**  
  - Pas de réponse → **OPEN|FILTERED**
- **Différence avec TCP** : comme UDP n’a pas de mécanisme de handshake, l’absence de réponse ne signifie pas forcément un port ouvert → ambiguïté inhérente.
- **Quand l’utiliser** : indispensable pour trouver des services UDP (DNS sur 53, SNMP sur 161, etc.), souvent oubliés par les scans TCP.

---

## 📊 États possibles des ports

| État             | Signification |
|------------------|---------------|
| **OPEN**         | Un service écoute activement sur ce port. |
| **CLOSED**       | Le port est accessible mais aucun service n’écoute. |
| **FILTERED**     | Un pare-feu bloque les paquets → aucune réponse. |
| **OPEN FILTERED** | Impossible de savoir : soit le port est ouvert et ne répond pas, soit il est filtré. |
| **UNFILTERED**   | Le port est joignable mais son état exact (ouvert/fermé) ne peut pas être déterminé. |

---
