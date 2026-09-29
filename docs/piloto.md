# Resultados do piloto

O projeto foi validado em três hosts com distribuições e agentes diferentes, todos executando exatamente o mesmo script, confirmado pelo hash `37ae12d3...`.

## Hosts

| Host | Sistema | Agente Zabbix | Particularidade |
|---|---|---|---|
| A | Rocky Linux 9.8 | agent2 | Grafana e plugins com binários Go |
| B | Debian 13 com Proxmox VE 9 | agent2 | Hypervisor com VMs de produção |
| C | Ubuntu 24.04 LTS | agent clássico | Executa o Zabbix proxy |

## Comparativo

| Medida | Host A | Host B | Host C |
|---|---|---|---|
| Duração da primeira coleta | 20 s | 53 s | 127 s |
| Duração com cache e filtro ajustado | 6 s | 3 s | 70 s |
| Achados de kernel antigo descartados | 2 232 | 0 | 26 536 |
| CVEs únicas | 55 | 583 | 3 390 |
| CVEs únicas CRITICAL | 0 | 9 | 5 |
| CVEs únicas HIGH | 32 | 132 | 163 |
| Corrigíveis HIGH (após ajustes) | 32 | 0 | 0 |
| Corrigíveis MEDIUM (após ajustes) | 19 | 0 | 4 |

A diferença em CVEs únicas entre os hosts reflete a quantidade e a idade dos pacotes instalados. Não indica falha de coleta.

## O que o piloto revelou

### Host A

As 32 CVEs HIGH corrigíveis estão em bibliotecas Go embutidas em binários do Grafana e de seus plugins, além do próprio trivy. Nenhum comando de sistema as corrige. A correção depende de atualizar o software.

O kernel antigo, que respondia por 362 das 394 CVEs HIGH aparentes, foi filtrado e depois removido do host.

### Host B

O trivy apontou 3 CVEs CRITICAL corrigíveis e o gerenciador de pacotes não tinha nada pendente. A causa eram pacotes Perl da versão anterior do Debian, sem repositório de origem. Depois de conferir dependências e simular a remoção, a limpeza zerou as três.

Uma segunda rodada removeu seis bibliotecas órfãs de versões anteriores (LDAP, ICU, ZFS e outras) e zerou as CVEs corrigíveis. O total de CVEs únicas caiu de 583 para 577, porque esses pacotes pequenos carregavam apenas uma CVE cada.

As 577 restantes não têm correção publicada.

### Host C

O filtro de kernel não reconhecia o prefixo `linux-tools-`. Pacotes de ferramentas do kernel antigo continuaram no ranking e geraram uma CVE corrigível falsa. Depois de incluir o prefixo os achados descartados subiram de 16 590 para 26 536 e as CVEs HIGH corrigíveis caíram de 3 para 0.

## Lições

O resumo das lições está em [licoes-aprendidas.md](licoes-aprendidas.md).
