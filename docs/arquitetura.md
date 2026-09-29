# Arquitetura

## Visão geral

A solução separa a coleta da leitura. Um timer do systemd executa o script como root uma vez por dia. O script grava um arquivo JSON em `/var/lib/zabbix-vuln/report.json`. O agente Zabbix lê esse arquivo com a chave nativa `vfs.file.contents`.

Um item mestre sem histórico recebe o JSON inteiro. Vinte e quatro itens dependentes extraem cada campo por JSONPath. Isso gera uma única leitura de arquivo por ciclo e muitos indicadores numéricos.

## Decisões de projeto

### Arquivo e timer em vez de UserParameter

A primeira ideia foi chamar o script por `UserParameter`, com `sudo` para o usuário `zabbix`. Dois problemas levaram ao abandono dessa abordagem.

A varredura do trivy leva de segundos a mais de dois minutos, conforme o host. Esse tempo pode ultrapassar o timeout do agente e fazer o item ficar não suportado.

Uma regra como `zabbix ALL=(ALL) NOPASSWD: /usr/bin/trivy rootfs *` também permite argumentos arbitrários. O usuário `zabbix` poderia usar opções como `--output` para sobrescrever arquivos como root.

No desenho atual o agente não executa nada. Ele só lê um arquivo de permissão `0644`, criado de forma atômica pelo script.

### Duas fontes de dados

O gerenciador de pacotes conhece os avisos de segurança do fornecedor da distribuição. Ele é leve e confiável para pacotes do sistema, mas não enxerga bibliotecas embutidas em binários.

O trivy enxerga pacotes do sistema e bibliotecas de linguagem (Go, Python, Node, Java), mas consulta a própria base de vulnerabilidades. As duas visões se complementam e às vezes divergem, o que é esperado.

### Indicador principal é a CVE corrigível

O trivy também relata CVEs que ainda não têm correção publicada. Essas não permitem nenhuma ação e inflam o total. Por isso as triggers usam a contagem de CVEs corrigíveis e não o total de CVEs únicas.

### Filtro de kernel antigo

Distribuições mantêm kernels antigos instalados. O trivy avalia cada versão e repete centenas de CVEs para cada uma. Em um host Ubuntu isso gerou mais de 26 mil achados de kernels que nem estavam em execução.

O script compara a versão de cada pacote de kernel com `uname -r`. Achados de kernels instalados e não carregados são descartados e contados à parte em `stale_kernel_findings`. Os nomes de pacote variam por distribuição.

| Família | Prefixos ou nomes reconhecidos |
|---|---|
| RPM | `kernel`, `kernel-core`, `kernel-modules`, `kernel-modules-core`, `kernel-modules-extra`, `kernel-devel`, `kernel-devel-matched`, `kernel-uki-virt`, `kernel-debug*`, `kernel-rt*` |
| Debian e Ubuntu | `linux-image-`, `linux-modules-`, `linux-headers-`, `linux-tools-`, `linux-cloud-tools-`, `linux-buildinfo-` |
| Proxmox VE | `pve-kernel-`, `proxmox-kernel-` |

Metapacotes sem número de versão no nome, como `linux-image-generic`, não são filtrados.

### Valor -1 para métrica indisponível

Os avisos de segurança por severidade só existem em distribuições RPM. Em hosts com apt o JSON não tem esses campos. Em vez de deixar o item não suportado, o template grava `-1` e um value map exibe `N/D (apt)`.

O valor -1 nunca deve entrar em cálculos ou gráficos como se fosse uma contagem.

### Uma única versão do script

O script é idêntico em todos os hosts. O que muda por host fica em `/etc/zabbix-vuln/extra-skip-dirs`. Isso permite comparar a versão instalada por `sha256sum` e evita divergência entre servidores.

Durante o piloto uma correção foi aplicada em dois hosts e esquecida em um terceiro. A divergência só apareceu ao comparar os hashes. Veja [licoes-aprendidas.md](licoes-aprendidas.md).

## Componentes

| Componente | Caminho | Função |
|---|---|---|
| Script | `/usr/local/sbin/vuln-collect.py` | Coleta, agrega e grava o JSON |
| Relatório | `/var/lib/zabbix-vuln/report.json` | Saída lida pelo agente |
| Exclusões por host | `/etc/zabbix-vuln/extra-skip-dirs` | Diretórios que o trivy ignora neste host |
| Cache do trivy | `/var/cache/trivy` | Base de vulnerabilidades |
| Service | `/etc/systemd/system/vuln-collect.service` | Executa o script com limites de recurso |
| Timer | `/etc/systemd/system/vuln-collect.timer` | Agenda a execução diária |

## Limites de recurso do service

| Diretiva | Padrão | Efeito |
|---|---|---|
| `Nice` | 19 | Menor prioridade de CPU |
| `IOSchedulingClass` | idle | Usa disco apenas quando ocioso |
| `CPUQuota` | 50% | Teto de meio núcleo. Use 30% em host de produção sensível |
| `MemoryMax` | 2G | Encerra o serviço se passar de 2 GiB |
| `TimeoutStartSec` | 90min | Prazo máximo de uma execução |

O timer usa `OnCalendar=*-*-* 02:00:00` com `RandomizedDelaySec=3h` e `Persistent=true`. O atraso aleatório espalha a carga entre servidores. Persistent executa a coleta perdida se o host estava desligado no horário.

## Formato do report.json

Um exemplo completo está em [../examples/report.example.json](../examples/report.example.json).

| Campo | Descrição |
|---|---|
| `timestamp` | Momento da coleta em segundos Unix |
| `hostname` | Nome do host segundo o kernel |
| `duration` | Duração da coleta em segundos |
| `status` | `ok` ou `error`. Vale `error` se o gerenciador de pacotes ou o trivy falharem |
| `pkgmgr.status` | Resultado da coleta do gerenciador de pacotes |
| `pkgmgr.tool` | `dnf`, `yum` ou `apt` |
| `pkgmgr.advisories` | Avisos por severidade (`Critical`, `Important`, `Moderate`, `Low`). Somente RPM |
| `pkgmgr.advisories_total` | Total de avisos de segurança pendentes. Somente RPM |
| `pkgmgr.cves_pending` | CVEs com patch no repositório. Somente RPM |
| `pkgmgr.packages_pending` | Pacotes com atualização de segurança pendente |
| `pkgmgr.reboot_required` | 1 se precisa reiniciar, 0 se não, -1 se não foi possível determinar |
| `pkgmgr.last_patch_days` | Dias desde o pacote instalado mais recente |
| `trivy.status` | `ok`, `error` ou `not_installed` |
| `trivy.running_kernel` | Resultado de `uname -r` |
| `trivy.stale_kernel_findings` | Achados de kernels antigos descartados |
| `trivy.unique_cves` | CVEs distintas por severidade |
| `trivy.fixable` | CVEs distintas com correção publicada, por severidade |
| `trivy.fixable_by_class` | O mesmo, separado em `os-pkgs` e `lang-pkgs` |
| `trivy.unique_total` | Total de CVEs distintas |
| `trivy.findings_by_class` | Achados brutos por classe, sem deduplicar |
| `trivy.oldest_fixable_crit_high_days` | Idade em dias da CVE CRITICAL ou HIGH corrigível mais antiga |
| `trivy.top_packages` | Até 15 pacotes com mais vulnerabilidades |
| `trivy.top_cves` | Até 15 CVEs de maior severidade e CVSS |

O script grava o arquivo em um temporário e o renomeia, então o agente nunca lê um JSON pela metade.

## Como interpretar os números

Considere um host Debian que, depois de aplicar todas as atualizações, mostra 577 CVEs únicas e zero CVEs corrigíveis.

As 577 CVEs existem e estão catalogadas. Nenhuma tem `FixedVersion` publicado, ou seja, nenhum fornecedor lançou o patch. Não há comando que resolva isso hoje. O que aumenta a segurança nesse caso é reduzir a superfície, removendo pacotes não usados, ou aceitar o risco de forma documentada.

Três contagens diferentes aparecem no relatório.

| Contagem | O que conta |
|---|---|
| Achados brutos (`findings_by_class`) | Cada linha do relatório do trivy, por pacote |
| CVEs únicas (`unique_total`) | Cada identificador uma vez, mesmo em vários pacotes |
| CVEs corrigíveis (`fixable`) | CVEs únicas que têm versão corrigida disponível |

Uma mesma CVE que atinge `kernel`, `kernel-core` e `kernel-modules` gera três achados e uma CVE única.

## Limitações conhecidas

- O campo `top_cves` guarda só 15 entradas ordenadas por severidade e CVSS. CVEs corrigíveis de severidade baixa podem ficar fora dele. Os contadores numéricos não têm esse limite.
- A métrica `last_patch_days` mede a última instalação de qualquer pacote, inclusive os que não são de segurança.
- O trivy só conhece o que a base de vulnerabilidades sabe. Uma base desatualizada gera falsa sensação de segurança. O monitoramento da idade da base está no [roadmap](roadmap.md).
- O script emite um aviso de descontinuação de `datetime.utcnow()` em Python 3.12 ou superior. O aviso não altera o resultado.
