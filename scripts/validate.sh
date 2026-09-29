#!/usr/bin/env bash
# Confere a instalacao do monitoramento de vulnerabilidades neste host.
# Uso (como root)
#   ./scripts/validate.sh
#   ./scripts/validate.sh <sha256_esperado_do_script>
# Sem argumento, o hash esperado e calculado a partir de src/vuln-collect.py do repositorio.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
REPORT="/var/lib/zabbix-vuln/report.json"
INSTALLED="/usr/local/sbin/vuln-collect.py"
EXPECTED="${1:-}"
[ -n "$EXPECTED" ] || EXPECTED="$(sha256sum "$REPO_DIR/src/vuln-collect.py" | awk '{print $1}')"
RC=0

ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[AVISO] %s\n' "$*"; }
bad()  { printf '[FALHA] %s\n' "$*"; RC=1; }

echo "== Host $(hostname) =="
. /etc/os-release 2>/dev/null && echo "Sistema ${PRETTY_NAME:-desconhecido} kernel $(uname -r)"

echo "== Componentes =="
if command -v trivy >/dev/null; then ok "trivy $(trivy --version | awk '/^Version:/ {print $2; exit}')"; else bad "trivy nao instalado"; fi
command -v jq >/dev/null && ok "jq presente" || warn "jq ausente, este validador usa jq"
if [ -f "$INSTALLED" ]; then
  ACTUAL="$(sha256sum "$INSTALLED" | awk '{print $1}')"
  if [ "$ACTUAL" = "$EXPECTED" ]; then ok "script identico ao repositorio ($ACTUAL)"; else bad "hash do script difere. instalado=$ACTUAL esperado=$EXPECTED"; fi
else
  bad "$INSTALLED nao encontrado"
fi
[ -f /etc/zabbix-vuln/extra-skip-dirs ] && ok "extra-skip-dirs presente" || warn "extra-skip-dirs ausente (opcional)"

echo "== Agendamento =="
if systemctl is-enabled vuln-collect.timer >/dev/null 2>&1; then ok "timer habilitado"; else bad "timer nao habilitado"; fi
systemctl list-timers vuln-collect.timer --no-pager 2>/dev/null | sed -n '1,3p'

echo "== Relatorio =="
if [ -f "$REPORT" ] && command -v jq >/dev/null; then
  TS="$(jq -r '.timestamp' "$REPORT")"
  AGE=$(( $(date +%s) - TS ))
  echo "Gerado em $(date -d @"$TS") ha $((AGE/3600)) horas"
  [ "$AGE" -lt 129600 ] && ok "relatorio com menos de 36 horas" || bad "relatorio desatualizado"
  jq -r '"status geral \(.status), duracao \(.duration)s",
         "pkgmgr \(.pkgmgr.status // "n/d"), trivy \(.trivy.status // "n/d")",
         "corrigiveis  CRITICAL=\(.trivy.fixable.CRITICAL) HIGH=\(.trivy.fixable.HIGH) MEDIUM=\(.trivy.fixable.MEDIUM) LOW=\(.trivy.fixable.LOW)",
         "unicas       CRITICAL=\(.trivy.unique_cves.CRITICAL) HIGH=\(.trivy.unique_cves.HIGH) total=\(.trivy.unique_total)",
         "kernels antigos ignorados \(.trivy.stale_kernel_findings), reboot pendente \(.pkgmgr.reboot_required)"' "$REPORT"
  [ "$(jq -r '.status' "$REPORT")" = "ok" ] || bad "status do relatorio diferente de ok"
else
  bad "relatorio ausente. rode systemctl start vuln-collect.service"
fi

echo "== Agente Zabbix =="
if id zabbix >/dev/null 2>&1; then
  if runuser -u zabbix -- cat "$REPORT" >/dev/null 2>&1; then ok "usuario zabbix le o relatorio"; else bad "usuario zabbix nao consegue ler $REPORT"; fi
else
  warn "usuario zabbix inexistente, agente nao instalado?"
fi
for svc in zabbix-agent2 zabbix-agent; do
  systemctl is-active "$svc" >/dev/null 2>&1 && ok "$svc ativo"
done
CONF="$(ls /etc/zabbix/zabbix_agent2.conf /etc/zabbix/zabbix_agentd.conf 2>/dev/null | head -n1)"
if [ -n "$CONF" ]; then
  SA="$(grep -E '^ServerActive=' "$CONF" || true)"
  HN="$(grep -E '^Hostname=' "$CONF" || true)"
  echo "$SA"; echo "$HN"
  [ -n "$SA" ] || bad "ServerActive ausente em $CONF, o item mestre e do tipo agente ativo"
  case "$SA" in *,*) warn "ServerActive com mais de um endereco. Enderecos separados por virgula sao tratados como nos de HA" ;; esac
fi

echo
[ "$RC" -eq 0 ] && echo "Resultado geral OK" || echo "Resultado geral com falhas"
exit "$RC"
