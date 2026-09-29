#!/usr/bin/env bash
# Instala o monitoramento de vulnerabilidades em um host Linux.
#
# Uso (como root, a partir da raiz do repositorio)
#   ./scripts/install.sh
#
# Variaveis opcionais de ambiente
#   TRIVY_VERSION  versao fixa do trivy (padrao 0.74.0)
#   ONCALENDAR     horario base do timer (padrao "*-*-* 02:00:00")
#   RANDOM_DELAY   atraso aleatorio do timer (padrao 3h)
#   CPU_QUOTA      limite de CPU do servico (padrao 50%)
#   MEMORY_MAX     limite de memoria do servico (padrao 2G)
#   RUN_NOW        1 executa uma coleta ao final (padrao 0)
#
# Exemplo em host sensivel, com limite menor e horario proprio
#   CPU_QUOTA=30% ONCALENDAR="*-*-* 04:00:00" RUN_NOW=1 ./scripts/install.sh
set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"
ONCALENDAR="${ONCALENDAR:-*-*-* 02:00:00}"
RANDOM_DELAY="${RANDOM_DELAY:-3h}"
CPU_QUOTA="${CPU_QUOTA:-50%}"
MEMORY_MAX="${MEMORY_MAX:-2G}"
RUN_NOW="${RUN_NOW:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR=""

log()  { printf '[install] %s\n' "$*"; }
fail() { printf '[install] ERRO %s\n' "$*" >&2; exit 1; }
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "execute como root"
[ -f "$REPO_DIR/src/vuln-collect.py" ] || fail "execute a partir de uma copia completa do repositorio"
command -v python3 >/dev/null || fail "python3 nao encontrado"
command -v systemctl >/dev/null || fail "systemd nao encontrado"

case "$(uname -m)" in
  x86_64) TRIVY_ARCH="64bit" ;;
  aarch64) TRIVY_ARCH="ARM64" ;;
  *) fail "arquitetura nao suportada por este instalador $(uname -m)" ;;
esac

# Versoes do trivy publicadas de forma maliciosa em 2026-03 (GHSA-69fq-xp46-6x23)
case "$TRIVY_VERSION" in
  0.69.4|0.69.5|0.69.6) fail "versao $TRIVY_VERSION do trivy foi comprometida, use outra" ;;
esac

. /etc/os-release
FAMILY=""
case " ${ID:-} ${ID_LIKE:-} " in
  *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) FAMILY="rpm" ;;
  *" debian "*|*" ubuntu "*) FAMILY="deb" ;;
esac
[ -n "$FAMILY" ] || fail "distribuicao nao reconhecida ID=${ID:-} ID_LIKE=${ID_LIKE:-}"
log "Sistema ${PRETTY_NAME:-desconhecido} familia $FAMILY"

install_dependencies() {
  if [ "$FAMILY" = "rpm" ]; then
    local pm; pm="$(command -v dnf || command -v yum)"
    log "Instalando jq e yum-utils (needs-restarting)"
    "$pm" install -y jq yum-utils
  else
    log "Instalando jq"
    apt-get update -qq
    apt-get install -y jq
  fi
}

install_trivy() {
  local current=""
  if command -v trivy >/dev/null; then
    current="$(trivy --version | awk '/^Version:/ {print $2; exit}')"
  fi
  if [ "$current" = "$TRIVY_VERSION" ]; then
    log "trivy $TRIVY_VERSION ja instalado"
    return
  fi
  [ -z "$current" ] || log "trivy $current encontrado, sera substituido pela $TRIVY_VERSION"

  local ext file base
  if [ "$FAMILY" = "rpm" ]; then ext="rpm"; else ext="deb"; fi
  file="trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.${ext}"
  base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
  TMP_DIR="$(mktemp -d)"

  log "Baixando $file"
  curl -fsSL -o "$TMP_DIR/$file" "$base/$file"
  curl -fsSL -o "$TMP_DIR/checksums.txt" "$base/trivy_${TRIVY_VERSION}_checksums.txt"

  log "Validando sha256"
  ( cd "$TMP_DIR" && grep " ${file}\$" checksums.txt | sha256sum -c - ) \
    || fail "checksum invalido para $file, instalacao abortada"

  log "Instalando $file"
  if [ "$FAMILY" = "rpm" ]; then
    "$(command -v dnf || command -v yum)" install -y "$TMP_DIR/$file"
  else
    apt-get install -y "$TMP_DIR/$file"
  fi
  trivy --version | head -1
}

install_files() {
  log "Instalando script em /usr/local/sbin/vuln-collect.py"
  install -m 0750 -o root -g root "$REPO_DIR/src/vuln-collect.py" /usr/local/sbin/vuln-collect.py

  mkdir -p /etc/zabbix-vuln
  if [ ! -f /etc/zabbix-vuln/extra-skip-dirs ]; then
    install -m 0644 "$REPO_DIR/config/extra-skip-dirs.example" /etc/zabbix-vuln/extra-skip-dirs
    log "Criado /etc/zabbix-vuln/extra-skip-dirs, edite se o host tiver storage grande"
  else
    log "Mantido /etc/zabbix-vuln/extra-skip-dirs existente"
  fi

  log "Instalando units systemd"
  sed -e "s|^CPUQuota=.*|CPUQuota=${CPU_QUOTA}|" \
      -e "s|^MemoryMax=.*|MemoryMax=${MEMORY_MAX}|" \
      "$REPO_DIR/systemd/vuln-collect.service" > /etc/systemd/system/vuln-collect.service
  sed -e "s|^OnCalendar=.*|OnCalendar=${ONCALENDAR}|" \
      -e "s|^RandomizedDelaySec=.*|RandomizedDelaySec=${RANDOM_DELAY}|" \
      "$REPO_DIR/systemd/vuln-collect.timer" > /etc/systemd/system/vuln-collect.timer
  chmod 0644 /etc/systemd/system/vuln-collect.service /etc/systemd/system/vuln-collect.timer

  systemctl daemon-reload
  systemctl enable --now vuln-collect.timer
}

install_dependencies
install_trivy
install_files

if [ "$RUN_NOW" = "1" ]; then
  log "Executando a primeira coleta, pode levar alguns minutos"
  systemctl start vuln-collect.service
fi

log "sha256 do script instalado"
sha256sum /usr/local/sbin/vuln-collect.py
systemctl list-timers vuln-collect.timer --no-pager || true
log "Concluido. Rode ./scripts/validate.sh para conferir o resultado."
