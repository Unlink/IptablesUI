# WireGuard Integration Guide

## 🔗 Network Stack Sharing

IptablesUI používa `network_mode: "container:wireguard"` pre zdieľanie network stack-u s WireGuard kontajnerom. Toto umožňuje priame upravovanie iptables pravidiel VPN servera.

## 📋 Dostupné konfigurácie

### 1. Kompletné riešenie (docker-compose.yml)
- WireGuard server + IptablesUI v jednom setup-e
- Automatická konfigurácia a dependencies
- **Odporúčané pre nové inštalácie**

### 2. Existujúci WireGuard (docker-compose.existing-wg.yml)
- Pripojenie IptablesUI k už existujúcemu WireGuard kontajneru
- Minimálne zmeny v existujúcom setup-e
- **Odporúčané pre existujúce VPN servery**

### 3. Standalone (docker-compose.standalone.yml)
- IptablesUI bez WireGuard
- Správa iptables na host systéme
- **Pre testovanie alebo iné firewall scenáre**

## 🚀 Deployment scenáre

### Scenár 1: Nová WireGuard inštalácia

```bash
# 1. Stiahnite hlavný docker-compose
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.yml

# 2. Upravte konfiguráciu
nano docker-compose.yml
# - Zmeňte ADMIN_PASS
# - Nastavte TZ (timezone)
# - Upravte PEERS (počet klientov)
# - Voliteľne SERVERURL

# 3. Vytvorte potrebné adresáre
mkdir -p wireguard data

# 4. Spustite služby
docker-compose up -d

# 5. Získajte QR kódy pre klientov
docker-compose logs wireguard

# 6. Prístup k IptablesUI
# http://your-server:8080
```

### Scenár 2: Existujúci WireGuard server

```bash
# 1. Zistite názov WireGuard kontajnera
docker ps | grep wireguard

# 2. Stiahnite compose pre existujúci WG
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.existing-wg.yml

# 3. Upravte názov kontajnera
sed -i 's/your-existing-wireguard-container/ACTUAL_CONTAINER_NAME/g' docker-compose.existing-wg.yml

# 4. Pridajte port 8080 k WireGuard kontajneru
docker stop ACTUAL_CONTAINER_NAME
docker run -d --name ACTUAL_CONTAINER_NAME \
  -p 8080:8080 \
  # ... kopírujte ostatné parametre z docker inspect ...

# 5. Spustite IptablesUI
docker-compose -f docker-compose.existing-wg.yml up -d
```

### Scenár 3: Testovanie bez WireGuard

```bash
# 1. Standalone konfigurácia
curl -O https://raw.githubusercontent.com/Unlink/IptablesUI/main/docker-compose.standalone.yml

# 2. Spustite
mkdir data
docker-compose -f docker-compose.standalone.yml up -d
```

## 🔧 Troubleshooting

### Problem: IptablesUI sa nespojí s WireGuard
```bash
# Skontrolujte názov WireGuard kontajnera
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

# Overte, že WireGuard beží
docker logs wireguard

# Skontrolujte network mode IptablesUI
docker inspect iptablesui | grep -i network
```

### Problem: Port 8080 nie je dostupný
```bash
# Overte, že WireGuard expose port 8080
docker port wireguard

# Ak nie, pridajte port:
docker stop wireguard
# Pridajte -p 8080:8080 do docker run príkazu
```

### Problem: Iptables príkazy nefungujú
```bash
# Skontrolujte capabilities WireGuard kontajnera
docker inspect wireguard | grep -i cap

# Overte, že WireGuard má NET_ADMIN
# WireGuard kontajner musí mať NET_ADMIN capability

# Test iptables v IptablesUI kontajneri
docker exec iptablesui iptables -L
```

### Problem: WireGuard peers sa nezobrazujú (Operation not permitted)
```bash
# Skontrolujte, či IptablesUI má NET_ADMIN capability
docker inspect iptablesui | grep -i cap

# Pridajte NET_ADMIN do docker-compose.yml
services:
  iptablesui:
    cap_add:
      - NET_ADMIN

# Reštartujte kontajner
docker-compose restart iptablesui

# Test wg príkazu v kontajneri
docker exec iptablesui wg show

# Debug informácie cez API
curl http://localhost:8080/api/debug/wireguard
```

### Problem: Rules sa neukladajú
```bash
# Skontrolujte volume mount
docker inspect iptablesui | grep -A 5 -i volume

# Overte oprávnienia data adresára
ls -la ./data/

# Test zapisu
docker exec iptablesui touch /app/data/test.txt
```

## 🔍 Monitoring

### Kontrola stavu
```bash
# Stav služieb
docker-compose ps

# Logy WireGuard
docker-compose logs wireguard

# Logy IptablesUI
docker-compose logs iptablesui

# Network stack info
docker exec iptablesui ip addr show
docker exec iptablesui iptables -L -n
```

### Performance monitoring
```bash
# CPU a pamäť
docker stats wireguard iptablesui

# Network traffic
docker exec iptablesui netstat -i

# Disk usage
du -sh ./wireguard ./data
```

## 🛡️ Security considerations

### Firewall rules
- IptablesUI môže upravovať všetky iptables pravidlá WireGuard servera
- Buďte opatrní s DROP rules, môžete sa vylockovať
- Vždy majte backup pravidiel cez Settings > Export

### Access control
- Zmeňte default ADMIN_PASS
- Používajte silné heslá
- Obmedzte prístup k portu 8080 pomocou iptables
- Zvážte reverse proxy s SSL/TLS

### Updates
```bash
# Update na najnovšiu verziu
docker-compose pull
docker-compose up -d

# Backup pred update
docker exec iptablesui cat /app/data/rules.json > backup-rules.json
```