# Histórico de mudanças

O formato segue o padrão Keep a Changelog e o versionamento segue SemVer.

## [1.0.0] - 2026-09-28

Primeira versão publicada, validada em três hosts piloto.

### Adicionado

- Script `src/vuln-collect.py` que combina o gerenciador de pacotes nativo e o trivy.
- Filtro de kernel antigo instalado, com prefixos RPM, Debian, Ubuntu e Proxmox.
- Arquivo opcional `/etc/zabbix-vuln/extra-skip-dirs` para exclusões por host.
- Units systemd `vuln-collect.service` e `vuln-collect.timer` com limites de CPU, memória e IO.
- Template Zabbix 7.0 com 25 itens, 8 triggers, 4 gráficos, 1 dashboard e 2 value maps.
- Instalador `scripts/install.sh`, validador `scripts/validate.sh` e desinstalador `scripts/uninstall.sh`.
- Testes automatizados do template e do script em `tests/`.

### Conhecido

- O script emite um aviso de descontinuação de `datetime.utcnow()` no Python 3.12 ou superior.
  O aviso vai para stderr e não afeta o resultado. A correção está no roadmap.
- O campo `top_cves` guarda apenas as 15 CVEs de maior severidade e CVSS.
  CVEs corrigíveis de severidade menor podem ficar fora do relatório.
