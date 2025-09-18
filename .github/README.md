# GitHub Actions Workflows

Tento projekt používa GitHub Actions pre CI/CD pipeline, automatické buildy a deployment do GitHub Container Registry.

## 📋 Workflows

### 1. `docker-build.yml` - Docker Build & Push
**Trigger:** Push na main/develop, tagy v*, pull requesty na main
**Funkcie:**
- Multi-platform build (linux/amd64, linux/arm64)
- Push do GitHub Container Registry (ghcr.io)
- Automatické tagovanie
- Build cache optimalizácia
- Artifact attestation

### 2. `ci.yml` - Continuous Integration  
**Trigger:** Push na main/develop, pull requesty
**Funkcie:**
- Lint check (flake8)
- Code formatting check (Black, isort)
- Python testovanie (3.11, 3.12)
- Docker build test
- Application startup test

### 3. `security-scan.yml` - Security Scanning
**Trigger:** Push na main, pull requesty, weekly schedule
**Funkcie:**
- Trivy vulnerability scanning
- SARIF upload do GitHub Security tab
- Critical/High vulnerability detection
- Weekly automated scans

### 4. `release.yml` - Release Management
**Trigger:** Git tags v*.*.*
**Funkcie:**
- Production build & push
- GitHub Release creation
- Release notes generation
- Attachment files (README, docker-compose)

## 🚀 Deployment Process

### Automatický Deployment

1. **Development:**
   ```bash
   git push origin develop
   # → Build & push ghcr.io/unlink/iptablesui:develop
   ```

2. **Production Release:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   # → Build multi-platform
   # → Push ghcr.io/unlink/iptablesui:v1.0.0
   # → Push ghcr.io/unlink/iptablesui:latest  
   # → Create GitHub Release
   ```

### Registry Images

- **Latest stable:** `ghcr.io/unlink/iptablesui:latest`
- **Tagged release:** `ghcr.io/unlink/iptablesui:v1.0.0`
- **Development:** `ghcr.io/unlink/iptablesui:develop`
- **Branch builds:** `ghcr.io/unlink/iptablesui:main`

## 🔧 Configuration

### Secrets (už nastavené)
- `GITHUB_TOKEN` - automaticky k dispozícii

### Permissions
Workflows používajú:
- `contents: read/write` - čítanie kódu, vytváranie releases
- `packages: write` - push do Container Registry
- `security-events: write` - upload security scans

### Environment Variables
```yaml
env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
```

## 📊 Monitoring

### Build Status
[![Docker Build](https://github.com/Unlink/IptablesUI/actions/workflows/docker-build.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/docker-build.yml)

### Security Status  
[![Security Scan](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/security-scan.yml)

### CI Status
[![CI/CD](https://github.com/Unlink/IptablesUI/actions/workflows/ci.yml/badge.svg)](https://github.com/Unlink/IptablesUI/actions/workflows/ci.yml)

## 🐛 Troubleshooting

### Build Failures
1. **Syntax errors:** Skontrolujte flake8 output v CI
2. **Docker build:** Overte Dockerfile syntax
3. **Tests failing:** Spustite testy lokálne

### Registry Issues
1. **Push permissions:** Overte GitHub token permissions
2. **Image size:** Optimalizujte Docker layers
3. **Platform support:** Testujte na linux/amd64 a linux/arm64

### Security Scans
1. **High vulnerabilities:** Update base image/dependencies
2. **False positives:** Pridajte do Trivy ignore list
3. **Weekly scans:** Pravidelne kontrolujte security tab

## 🔄 Maintenance

### Regular Tasks
- Update base image v Dockerfile
- Update GitHub Actions versions
- Review security scan results
- Clean up old container images

### Version Updates
```bash
# Update major version
git tag v2.0.0
git push origin v2.0.0

# Update minor version  
git tag v1.1.0
git push origin v1.1.0

# Update patch version
git tag v1.0.1
git push origin v1.0.1
```