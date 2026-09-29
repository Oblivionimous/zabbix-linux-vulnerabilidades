#!/usr/bin/env bash
# Remove o monitoramento de vulnerabilidades deste host.
# Uso (como root)
#   ./scripts/uninstall.sh          remove timer, service e script
#   ./scripts/uninstall.sh --purge  remove tambem relatorio, configuracao e cache do trivy
# O pacote trivy nao e removido.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "execute como root" >&2; exit 1; }

systemctl disable --now vuln-collect.timer 2>/dev/null || true
systemctl stop vuln-collect.service 2>/dev/null || true
rm -f /etc/systemd/system/vuln-collect.service /etc/systemd/system/vuln-collect.timer
systemctl daemon-reload
rm -f /usr/local/sbin/vuln-collect.py
echo "Timer, service e script removidos."

if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/lib/zabbix-vuln /etc/zabbix-vuln /var/cache/trivy
  echo "Relatorio, configuracao e cache removidos."
fi
