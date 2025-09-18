# Deployment Guide

## GitHub Container Registry

Tento projekt automaticky buildne a pushuje Docker images do GitHub Container Registry pomocou GitHub Actions.

### Dostupné Images

- **Latest**: `ghcr.io/unlink/iptablesui:latest`
- **Tagged versions**: `ghcr.io/unlink/iptablesui:v1.0.0`
- **Branch builds**: `ghcr.io/unlink/iptablesui:main`

### Automatické Builds

GitHub Actions automaticky spúšťa build pri:
- Push do `main` alebo `develop` branch
- Vytvorení nového tagu `v*.*.*`
- Pull requeste do `main` branch

### Tagging a Releases

Pre vytvorenie nového release:

```bash
# Vytvorte nový tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions automaticky:
# 1. Buildne multi-platform image (linux/amd64, linux/arm64)
# 2. Pushne do ghcr.io
# 3. Vytvorí GitHub Release
# 4. Pripojí deployment súbory
```

### Security Scanning

Projekt automaticky skenuje Docker images na bezpečnostné zraniteľnosti pomocou Trivy:
- Weekly scans každý pondelok
- Scan pri každom PR a push
- Výsledky sa nahrajú do GitHub Security tab

### Manual Deployment

#### 1. Pomocou Docker
```bash
docker pull ghcr.io/unlink/iptablesui:latest
docker run -d --name iptablesui --privileged \
  -p 8080:8080 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=secure_password \
  -v ./data:/app/data \
  ghcr.io/unlink/iptablesui:latest
```

#### 2. Pomocou Docker Compose
```bash
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.yml
docker-compose up -d
```

#### 3. Pre WireGuard integráciu (odporúčané)

**Kompletné riešenie s WireGuard:**
```bash
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.yml
docker-compose up -d
```

**Pripojenie k existujúcemu WireGuard kontajneru:**
```bash
# Stiahnite a upravte
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.existing-wg.yml
# Upravte názov kontajnera v súbore
docker-compose -f docker-compose.existing-wg.yml up -d
```

**Kľúčové výhody:**
- Zdieľaný network stack medzi WireGuard a IptablesUI
- Priame upravovanie iptables pravidiel VPN servera
- Automatické dependencies a reštartovanie

**Štruktúra:**
```yaml
services:
  wireguard:
    image: linuxserver/wireguard
    ports:
      - "51820:51820/udp"  # WireGuard
      - "8080:8080"        # IptablesUI (zdieľaný port)
    cap_add:
      - NET_ADMIN
      - SYS_MODULE

  iptablesui:
    image: ghcr.io/unlink/iptablesui:latest
    network_mode: "container:wireguard"  # Zdieľaný network stack
    cap_add:
      - NET_ADMIN  # Potrebné pre iptables a wg príkazy
    depends_on:
      - wireguard
```

## Oprávnenia a Bezpečnosť

### Potrebné Docker capabilities

IptablesUI vyžaduje **NET_ADMIN** capability pre:
- **iptables** príkazy (pridávanie/mazanie firewall pravidiel)
- **wg** príkazy (čítanie WireGuard peer informácií) 
- **ip** príkazy (sledovanie sieťových rozhraní)

### Bezpečné nastavenie oprávnení

**Odporúčané (minimálne oprávnenia):**
```yaml
cap_add:
  - NET_ADMIN
```

**Alternatíva (všetky oprávnenia, menej bezpečné):**
```yaml
privileged: true
```

### Troubleshooting oprávnení

**Chyba "Operation not permitted" pri wg príkazoch:**
```bash
# Skontrolujte capabilities
docker exec iptablesui cat /proc/self/status | grep Cap

# Pridajte NET_ADMIN do docker-compose.yml
cap_add:
  - NET_ADMIN
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USER` | admin | Admin username |
| `ADMIN_PASS` | password | Admin password |
| `SECRET_KEY` | dev-secret-key-change-in-production | Flask secret key |
| `FLASK_ENV` | production | Flask environment |

### Health Checks

Image obsahuje health check endpoint:
```bash
curl -f http://localhost:8080/login
```

Docker Compose automaticky používa health check pre monitoring.

### Volumes

Mount `/app/data` pre persistent storage:
- `rules.json` - uložené pravidlá

### Networks

Pre WireGuard integráciu používajte custom network:
```bash
docker network create wireguard_net
```

### Troubleshooting

1. **Container sa nespustí**
   - Skontrolujte `--privileged` flag
   - Overte prístup k portu 8080

2. **Iptables príkazy nefungujú**
   - Container potrebuje NET_ADMIN capabilities
   - Musí byť spustený ako root

3. **Rules sa neukladajú**
   - Mount volume pre `/app/data`
   - Skontrolujte oprávnienia

### Update Process

1. **Pre latest verziu:**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

2. **Pre špecifickú verziu:**
   ```bash
   # V docker-compose.yml zmeňte tag
   image: ghcr.io/unlink/iptablesui:v1.1.0
   docker-compose up -d
   ```