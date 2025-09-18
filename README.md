# IptablesUI - Web GUI pre správu firewall pravidiel

[![Docker Build](https://github.com/Unlink/IptablesUI/actions/workflows/docker-build.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/docker-build.yml)
[![Security Scan](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml)
[![Security Scan](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml)
[![CI/CD](https://github.com/Unlink/IptablesUI/actions/workflows/ci.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/ci.yml)

Jednoduchá webová aplikácia pre správu iptables firewall pravidiel s Docker podporou.

## 🚀 Quick Start

```bash
docker run -d --name iptablesui --privileged \
  -p 8080:8080 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_password \
  ghcr.io/unlink/iptablesui:latest
```

Aplikácia bude dostupná na `http://localhost:8080`

## Popis

IptablesUI je Flask webová aplikácia, ktorá poskytuje grafické používateľské rozhranie pre správu iptables pravidiel v Linux kontajneroch. Aplikácia je optimalizovaná pre WireGuard VPN servery a umožňuje:

- Prezeranie aktuálnych iptables pravidiel
- Pridávanie nových pravidiel cez formulár s WireGuard hints
- **Automatické načítanie WireGuard peer informácií**
- **Quick-fill funkcionalita pre WireGuard IP adresy**
- **Zobrazenie aktívnych VPN pripojení**
- Export/import pravidiel do/z JSON formátu
- Automatické uloženie a načítanie pravidiel pri reštarte

## 🔥 WireGuard funkcie

### Automatická detekcia peers
- Čítanie WireGuard konfiguračných súborov
- Zobrazenie nakonfigurovaných a aktívnych peers
- Real-time status aktívnych pripojení

### Smart hints pri pridávaní pravidiel
- Quick-copy IP adries z peer zoznamu
- Predvyplnené formuláre pre bežné WireGuard scenáre
- Automatické návrhy na základe VPN topológie

## Funkcie

### Dashboard
- Zobrazenie všetkých aktuálnych iptables pravidiel
- Farebné označenie typov pravidiel (INPUT/FORWARD/OUTPUT)
- Označenie akcií (ACCEPT/DROP/REJECT)
- Označenie protokolov (TCP/UDP/ICMP)

### Pridanie pravidla
- Formulár pre konfiguráciu nového pravidla
- Podporované parametre:
  - Chain (INPUT/FORWARD/OUTPUT)
  - Protokol (TCP/UDP/ICMP alebo ľubovoľný)
  - Zdrojová IP adresa/sieť
  - Cieľová IP adresa/sieť
  - Port (pre TCP/UDP)
  - Akcia (ACCEPT/DROP/REJECT)

### Nastavenia
- Export všetkých pravidiel do JSON formátu
- Import pravidiel z JSON formátu
- Vymazanie všetkých pravidiel
- Zobrazenie stavu a štatistík

## Technické detaily

### Požiadavky
- **Operačný systém:** Linux (Ubuntu, Debian, CentOS, atď.) alebo macOS s Docker
- **Python:** 3.11+ (len pre lokálnu inštaláciu)
- **Flask:** 2.3+ (len pre lokálnu inštaláciu)
- **Systémové nástroje:** iptables (dostupné v Linux kontajneri)
- **Docker:** Odporúčané pre jednoduchý deployment

**Poznámka:** Aplikácia vyžaduje Linux prostredie pre iptables funkcionalitu. Na macOS a Windows používajte Docker.

### Štruktúra projektu
```
IptablesUI/
├── app.py                        # Hlavná Flask aplikácia
├── requirements.txt              # Python závislosti (aktualizované pre CVE)
├── Dockerfile                    # Docker konfigurácia
├── docker-compose.yml            # WireGuard + IptablesUI setup
├── docker-compose.standalone.yml # Standalone IptablesUI
├── docker-compose.existing-wg.yml # Pre existujúci WireGuard
├── start.sh                      # Unix štartovací script
├── README.md                     # Základná dokumentácia
├── DEPLOYMENT.md                 # Deployment guide
├── WIREGUARD.md                  # WireGuard integrácia guide
├── SECURITY.md                   # Bezpečnostné informácie
└── templates/
    ├── base.html                 # Základný template
    ├── dashboard.html            # Hlavný dashboard s WG peermi
    ├── login.html                # Prihlásenie
    └── add_rule.html             # Pridanie iptables pravidla
├── example-rules.json            # Príklad pravidiel
├── .github/                      # GitHub Actions workflows
│   ├── workflows/                # CI/CD workflows
│   └── ISSUE_TEMPLATE/           # Issue templates
└── templates/                    # HTML šablóny
    ├── base.html                 # Základná šablóna
    ├── login.html                # Prihlásenie
    ├── dashboard.html            # Dashboard
    ├── add_rule.html             # Pridanie pravidla
    └── settings.html             # Nastavenia
```

## Inštalácia a spustenie

### Docker (odporúčané)

#### GitHub Container Registry (najjednoduchšie)
```bash
docker run -d \
  --name iptablesui \
  --privileged \
  -p 8080:8080 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_secure_password \
  -v ./data:/app/data \
  ghcr.io/unlink/iptablesui:latest
```

#### Docker Compose s GitHub Registry
```bash
# Stiahnite docker-compose.yml z repository
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.yml
# Upravte premenné v súbore a spustite
docker-compose up -d
```

#### Lokálne buildovanie
1. **Buildovanie Docker image:**
```bash
docker build -t iptablesui .
```

2. **Spustenie kontajnera:**
```bash
docker run -d \
  --name iptablesui \
  --privileged \
  -p 8080:8080 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_secure_password \
  -v ./data:/app/data \
  iptablesui
```

**Dôležité:** Kontajner musí bežať s `--cap-add=NET_ADMIN` oprávnením pre prístup k iptables a WireGuard príkazom.

**Bezpečné nastavenie:**
```bash
docker run -d --name iptablesui \
  --cap-add=NET_ADMIN \
  -p 8080:8080 \
  -v ./data:/app/data \
  iptablesui
```

**Alternatívne (menej bezpečné):**
```bash
docker run -d --name iptablesui \
  --privileged \
  -p 8080:8080 \
  -v ./data:/app/data \
  iptablesui
```

### WireGuard integrácia (odporúčané)

#### Kompletné riešenie s WireGuard
Štandardný docker-compose.yml obsahuje WireGuard server s IptablesUI:

```bash
# Naklonujte repository alebo stiahnite docker-compose.yml
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.yml

# Upravte premenné podľa potreby
nano docker-compose.yml

# Spustite oba služby
docker-compose up -d
```

**Výhody:**
- IptablesUI zdieľa network stack s WireGuard kontajnerom
- Priame upravovanie iptables pravidiel WireGuard servera  
- Automatická závislosť a reštartovanie
- Prístup k WireGuard na porte 51820/udp a IptablesUI na porte 8080

#### Pripojenie k existujúcemu WireGuard kontajneru
Ak už máte WireGuard kontajner:

```bash
# Stiahnite špeciálny compose súbor
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.existing-wg.yml

# Upravte názov WireGuard kontajnera
sed -i 's/your-existing-wireguard-container/your_container_name/g' docker-compose.existing-wg.yml

# Pridajte port 8080 do existujúceho WireGuard kontajnera
docker stop your_container_name
docker run -d --name your_container_name \
  -p 8080:8080 \  # Pridajte túto linku
  -p 51820:51820/udp \
  # ... ostatné parametre ...

# Spustite IptablesUI
docker-compose -f docker-compose.existing-wg.yml up -d
```

#### Samostatná inštalácia (bez WireGuard)
Pre správu iptables na host systéme:

```bash
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.standalone.yml
docker-compose -f docker-compose.standalone.yml up -d
```

### Manuálna inštalácia (Linux/macOS)

1. **Nainštalovanie závislostí:**
```bash
pip install -r requirements.txt
```

2. **Spustenie aplikácie:**
```bash
export ADMIN_USER=admin
export ADMIN_PASS=password
python app.py
```

### Startup Script (Linux/macOS)

Pre jednoduchý štart je dostupný Unix script:

```bash
# Použitie GitHub Container Registry (default)
chmod +x start.sh
./start.sh

# Alebo lokálne buildovanie
./start.sh --local
```

## Použitie

1. **Prístup k aplikácii:**
   - Otvorte web browser a prejdite na `http://localhost:8080`
   - Prihláste sa s nastaveným username/password

2. **Dashboard:**
   - Zobrazí všetky aktuálne iptables pravidlá
   - Kliknite "Refresh" pre aktualizáciu

3. **Pridanie pravidla:**
   - Kliknite "Add Rule"
   - Vyplňte formulár s parametrami pravidla
   - Pravidlo sa okamžite aplikuje a uloží

4. **Nastavenia:**
   - Export: Exportuje všetky pravidlá do JSON
   - Import: Importuje pravidlá z JSON (prepíše existujúce)
   - Clear: Vymaže všetky pravidlá

## Príklady pravidiel

### Povoliť SSH
- Chain: INPUT
- Protocol: TCP  
- Port: 22
- Action: ACCEPT

### Blokovať špecifickú IP
- Chain: INPUT
- Source IP: 1.2.3.4
- Action: DROP

### Povoliť lokálnu sieť
- Chain: INPUT
- Source IP: 192.168.1.0/24
- Action: ACCEPT

## Bezpečnosť

**Aktualizované závislosti (2024-12-24):** Všetky HIGH severity CVE vulnerabilities boli vyriešené aktualizáciou na Flask 3.0.3 a Werkzeug 3.0.4. Detaily v [SECURITY.md](SECURITY.md).

- **Autentifikácia:** Jednoduchá username/password autentifikácia
- **Odporúčania:**
  - Zmeňte predvolené prihlasovacie údaje (`admin/admin`)
  - Používajte silné heslo
  - Obmedzte prístup k portu 8080
  - Pravidelne aktualizujte závislosti
- **CVE Status:** Všetky známe HIGH severity vulnerabilities vyriešené
  - Pravidelne zálohujte rules.json

## JSON formát pravidiel

```json
[
  {
    "chain": "INPUT",
    "protocol": "tcp",
    "source_ip": "192.168.1.0/24",
    "dest_ip": "",
    "port": "22",
    "action": "ACCEPT"
  }
]
```

## Environment Variables

- `ADMIN_USER`: Používateľské meno (default: admin)
- `ADMIN_PASS`: Heslo (default: password)
- `SECRET_KEY`: Flask secret key (default: dev-secret-key-change-in-production)

## Obmedzenia

- Aplikácia vyžaduje root prístup pre iptables príkazy
- Pravidlá sa aplikujú okamžite bez validácie
- Jednoduchá autentifikácia bez pokročilých funkcií
- Nepodporuje komplexné iptables funkcie (NAT, mangle tabuľky, atď.)

## Troubleshooting

### Kontajner sa nespustí
- Skontrolujte, či je Docker spustený s privilegovanými právami
- Overte, že port 8080 nie je obsadený

### Iptables príkazy nefungujú
- Skontrolujte, či kontajner má prístup k NET_ADMIN capabilities
- Overte, že iptables je nainštalovaný v kontajneri

### WireGuard peers sa nezobrazujú alebo chyba "Operation not permitted"
- Overte, že `cap_add: NET_ADMIN` je nastavený v docker-compose.yml
- Pre network_mode: "container:..." musí mať IptablesUI vlastné NET_ADMIN oprávnenie
- Skontrolujte logy: `docker-compose logs iptablesui`
- Použite debug endpoint: http://localhost:8080/api/debug/wireguard

### Pravidlá sa neukladajú
- Skontrolujte oprávnienia k súboru rules.json
- Overte mount point pre volume

### WireGuard peers sa nezobrazujú
- Overte, že network_mode: "container:wireguard" je nastavený
- Skontrolujte, či WireGuard kontajner beží
- Skontrolujte logy: `docker-compose logs iptablesui`

## Dokumentácia

Pre podrobné informácie o deployment a WireGuard integrácii:
- [DEPLOYMENT.md](DEPLOYMENT.md) - Kompletný deployment guide
- [WIREGUARD.md](WIREGUARD.md) - WireGuard integrácia
- [SECURITY.md](SECURITY.md) - Bezpečnostné informácie

**Projekt je pripravený na produkčné použitie s bezpečnými závislosťami a plnou WireGuard integráciou.**

## Licencia

Tento projekt je licencovaný pod MIT licenciou.