# Histórico de mudanças

O formato segue o padrão Keep a Changelog e o versionamento segue SemVer.

## [Não publicado]

### Adicionado

- Dashboard Grafana Classic para publicação no catálogo da comunidade, com seleção da fonte Zabbix durante a importação.
- Galeria com capturas de testes reais do dashboard Zabbix e Latest data no Zabbix 7.0.31, além de uma ilustração da verificação da coleta.
- Diagrama SVG do fluxo entre Linux, Zabbix e Grafana.
- Export Grafana V2 com marcador de UID da fonte Zabbix, sem metadados internos da instância de origem.
- JavaScript, CSS e Content do painel Business Text extraídos para revisão.
- Prévia local do Grafana com dados simulados.

### Alterado

- Terminologia padronizada para hosts na documentação, no painel Grafana e no diagrama.
- Legendas e textos alternativos das capturas Zabbix identificam o ambiente de testes reais.
- Contagem da galeria corrigida para um item mestre e 24 dependentes.
- Guias Zabbix e Grafana com importação, validação, consultas, filtros e limites de interpretação.
- Correção da sintaxe de `ServerActive` e dos níveis de configuração de macros.
- Documentação do índice de saúde, dos limites dos rankings e da soma de CVEs por host.
- Janela inicial do dashboard para as últimas `48h`, com atualização a cada `5m`.
- Descrições do template sobre apt, timestamp, macros e idade de CVEs, sem alterar chaves, UUIDs ou expressões.
- Referência gerada com inventário quantitativo do template e saída LF.

### Removido

- Documentos de preparação da publicação e melhorias planejadas, com ajuste das referências nos guias.

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
  O aviso vai para stderr e não afeta o resultado.
- O campo `top_cves` guarda apenas as 15 CVEs de maior severidade e CVSS.
  CVEs corrigíveis de severidade menor podem ficar fora do relatório.
