# Referência do template

Este arquivo é gerado por `tests/gerar_referencia.py` a partir de `zabbix/template_linux_vulnerabilidades.yaml`. Não edite à mão.

## Identificação

| Campo | Valor |
|---|---|
| Nome | Linux vulnerabilidades by Zabbix agent active |
| Fornecedor | Mauro Paiva |
| Versão | 7.0 |
| Grupo | Templates/Security |
| Tags do template | `scope: security`, `target: linux` |

## Item mestre

O item `vfs.file.contents[/var/lib/zabbix-vuln/report.json]` do tipo agente ativo lê o arquivo JSON a cada 30m e não guarda histórico. Todos os demais itens são dependentes dele e extraem campos por JSONPath.

## Itens

| Nome | Chave | Tipo | Valor | Histórico | Componente | JSONPath |
|---|---|---|---|---|---|---|
| Vuln: relatório JSON | `vfs.file.contents[/var/lib/zabbix-vuln/report.json]` | ZABBIX_ACTIVE | TEXT | 0 | coleta | `arquivo JSON completo` |
| Vuln: status da coleta | `vuln.scan.status` | DEPENDENT | CHAR | 30d | coleta | `$.status` |
| Vuln: horário da última coleta | `vuln.scan.timestamp` | DEPENDENT | UNSIGNED | 30d | coleta | `$.timestamp` |
| Vuln: duração da coleta | `vuln.scan.duration` | DEPENDENT | UNSIGNED | 30d | coleta | `$.duration` |
| Vuln: CVEs corrigíveis CRITICAL | `vuln.trivy.fixable[CRITICAL]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.fixable.CRITICAL` |
| Vuln: CVEs corrigíveis HIGH | `vuln.trivy.fixable[HIGH]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.fixable.HIGH` |
| Vuln: CVEs corrigíveis MEDIUM | `vuln.trivy.fixable[MEDIUM]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.fixable.MEDIUM` |
| Vuln: CVEs corrigíveis LOW | `vuln.trivy.fixable[LOW]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.fixable.LOW` |
| Vuln: CVEs corrigíveis CRITICAL em pacotes do SO | `vuln.trivy.fixable.os[CRITICAL]` | DEPENDENT | UNSIGNED | 90d | so | `$.trivy.fixable_by_class['os-pkgs'].CRITICAL` |
| Vuln: CVEs corrigíveis HIGH em pacotes do SO | `vuln.trivy.fixable.os[HIGH]` | DEPENDENT | UNSIGNED | 90d | so | `$.trivy.fixable_by_class['os-pkgs'].HIGH` |
| Vuln: CVEs corrigíveis CRITICAL em aplicações | `vuln.trivy.fixable.lang[CRITICAL]` | DEPENDENT | UNSIGNED | 90d | aplicacao | `$.trivy.fixable_by_class['lang-pkgs'].CRITICAL` |
| Vuln: CVEs corrigíveis HIGH em aplicações | `vuln.trivy.fixable.lang[HIGH]` | DEPENDENT | UNSIGNED | 90d | aplicacao | `$.trivy.fixable_by_class['lang-pkgs'].HIGH` |
| Vuln: CVEs únicas CRITICAL | `vuln.trivy.cves[CRITICAL]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.unique_cves.CRITICAL` |
| Vuln: CVEs únicas HIGH | `vuln.trivy.cves[HIGH]` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.unique_cves.HIGH` |
| Vuln: total de CVEs únicas | `vuln.trivy.cves.total` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.unique_total` |
| Vuln: idade da CVE CRITICAL/HIGH corrigível mais antiga (dias) | `vuln.trivy.oldest_days` | DEPENDENT | UNSIGNED | 90d | cve | `$.trivy.oldest_fixable_crit_high_days` |
| Vuln: achados em kernels antigos instalados | `vuln.trivy.stale_kernel` | DEPENDENT | UNSIGNED | 90d | kernel | `$.trivy.stale_kernel_findings` |
| Vuln: advisories de segurança Critical pendentes | `vuln.pkg.advisories[Critical]` | DEPENDENT | FLOAT (Métrica não suportada em apt) | 90d | so | `$.pkgmgr.advisories.Critical` |
| Vuln: advisories de segurança Important pendentes | `vuln.pkg.advisories[Important]` | DEPENDENT | FLOAT (Métrica não suportada em apt) | 90d | so | `$.pkgmgr.advisories.Important` |
| Vuln: total de advisories de segurança pendentes | `vuln.pkg.advisories.total` | DEPENDENT | FLOAT (Métrica não suportada em apt) | 90d | so | `$.pkgmgr.advisories_total` |
| Vuln: CVEs com patch disponível no repositório | `vuln.pkg.cves_pending` | DEPENDENT | FLOAT (Métrica não suportada em apt) | 90d | so | `$.pkgmgr.cves_pending` |
| Vuln: reboot pendente | `vuln.pkg.reboot_required` | DEPENDENT | FLOAT (Reboot pendente) | 90d | so | `$.pkgmgr.reboot_required` |
| Vuln: dias desde a última instalação de pacote | `vuln.pkg.last_patch_days` | DEPENDENT | UNSIGNED | 90d | so | `$.pkgmgr.last_patch_days` |
| Vuln: ranking de pacotes | `vuln.rank.packages` | DEPENDENT | TEXT | 7d | ranking | `$.trivy.top_packages` |
| Vuln: ranking de CVEs | `vuln.rank.cves` | DEPENDENT | TEXT | 7d | ranking | `$.trivy.top_cves` |

## Triggers

| Nome | Prioridade | Expressão | Escopo | Componente |
|---|---|---|---|---|
| Vuln: coleta de vulnerabilidades com erro | Atenção | `last(/vuln.scan.status)<>"ok"` | availability | coleta |
| Vuln: coleta desatualizada (mais de {$VULN.SCAN.MAX.AGE}) | Atenção | `now()-last(/vuln.scan.timestamp)>{$VULN.SCAN.MAX.AGE}` | availability | coleta |
| Vuln: CVE CRITICAL corrigível em pacote do SO | Alta | `last(/vuln.trivy.fixable.os[CRITICAL])>{$VULN.OS.CRIT.MAX}` | security | so |
| Vuln: CVEs HIGH corrigíveis em pacotes do SO acima do limite | Média | `last(/vuln.trivy.fixable.os[HIGH])>{$VULN.OS.HIGH.MAX}` | security | so |
| Vuln: CVE CRITICAL corrigível em aplicação ou biblioteca | Média | `last(/vuln.trivy.fixable.lang[CRITICAL])>{$VULN.LANG.CRIT.MAX}` | security | aplicacao |
| Vuln: advisory de segurança Critical pendente | Alta | `last(/vuln.pkg.advisories[Critical])>0` | security | so |
| Vuln: reboot pendente há mais de {$VULN.REBOOT.MAX} | Atenção | `min(/vuln.pkg.reboot_required,{$VULN.REBOOT.MAX})=1` | configuration | so |
| Vuln: sem atualização de pacotes há mais de {$VULN.PATCH.MAX.DAYS} dias | Informação | `last(/vuln.pkg.last_patch_days)>{$VULN.PATCH.MAX.DAYS}` | configuration | so |

## Macros

| Macro | Padrão | Uso |
|---|---|---|
| `{$VULN.LANG.CRIT.MAX}` | `0` | Limite de CVEs CRITICAL corrigíveis em aplicações a partir do qual a trigger dispara. |
| `{$VULN.OS.CRIT.MAX}` | `0` | Limite de CVEs CRITICAL corrigíveis em pacotes do SO a partir do qual a trigger dispara. |
| `{$VULN.OS.HIGH.MAX}` | `0` | Limite de CVEs HIGH corrigíveis em pacotes do SO a partir do qual a trigger dispara. |
| `{$VULN.PATCH.MAX.DAYS}` | `60` | Dias sem instalação de pacote antes de disparar o alerta informativo. |
| `{$VULN.REBOOT.MAX}` | `7d` | Tempo máximo que um reboot pode ficar pendente antes de disparar o alerta. |
| `{$VULN.SCAN.MAX.AGE}` | `36h` | Idade máxima do relatório antes de considerar a coleta desatualizada. |

## Gráficos

| Nome | Itens |
|---|---|
| Vuln: CVEs corrigíveis por severidade | `vuln.trivy.fixable[CRITICAL]`, `vuln.trivy.fixable[HIGH]`, `vuln.trivy.fixable[MEDIUM]`, `vuln.trivy.fixable[LOW]` |
| Vuln: CVEs corrigíveis por classe (CRITICAL e HIGH) | `vuln.trivy.fixable.os[CRITICAL]`, `vuln.trivy.fixable.os[HIGH]`, `vuln.trivy.fixable.lang[CRITICAL]`, `vuln.trivy.fixable.lang[HIGH]` |
| Vuln: CVEs únicas vs corrigíveis (CRITICAL e HIGH) | `vuln.trivy.cves[CRITICAL]`, `vuln.trivy.fixable[CRITICAL]`, `vuln.trivy.cves[HIGH]`, `vuln.trivy.fixable[HIGH]` |
| Vuln: duração da coleta | `vuln.scan.duration` |

## Dashboard do host

O dashboard "Vulnerabilidades - visão geral" aparece em Monitoring > Hosts > Dashboards.

Página `Situação atual`

| Widget | Tipo | Posição (x, y) | Tamanho (largura x altura) |
|---|---|---|---|
| Alertas de vulnerabilidade em aberto | `problems` | 0, 0 | 72 x 4 |
| CVEs corrigíveis por severidade | `svggraph` | 0, 4 | 36 x 6 |
| CVEs corrigíveis: SO vs aplicações | `svggraph` | 36, 4 | 36 x 6 |

## Value maps

### Reboot pendente

| Valor | Exibição |
|---|---|
| -1 | N/D |
| 0 | Não |
| 1 | Sim |

### Métrica não suportada em apt

| Valor | Exibição |
|---|---|
| -1 | N/D (apt) |
