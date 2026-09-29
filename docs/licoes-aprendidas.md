# Lições aprendidas

Cada linha descreve um problema real encontrado durante a construção e o que foi feito.

## Coleta e segurança

| Problema | Causa | Solução |
|---|---|---|
| Timeout e risco de segurança no modelo inicial | `UserParameter` chamando o trivy por `sudo` com curinga nos argumentos | Coleta agendada como root e leitura de arquivo pelo agente |
| Instalação do trivy sem garantia de origem | Script de instalação que baixa a versão mais recente sem conferência, em meio ao ataque à cadeia de suprimentos de março de 2026 | Pacote da release com versão fixa e validação de `sha256`. O instalador recusa 0.69.4, 0.69.5 e 0.69.6 |
| `dnf` inteiro falhando | Repositório `pkg.aquasec.com` sem resolução de DNS | Remover o `.repo` e usar o pacote da release do GitHub |
| Milhares de CVEs de kernel | Kernels antigos instalados avaliados um a um | Filtro por versão do kernel em execução |
| Filtro de kernel incompleto | Cada distribuição nomeia os pacotes de forma diferente (`kernel-*`, `proxmox-kernel-*`, `linux-tools-*`) | Lista de prefixos por família e testes automatizados |
| Cópias divergentes do script | Correção aplicada em dois hosts e esquecida no terceiro | Comparação por `sha256sum` e regra de versão única. Ideia de gravar a versão no relatório está no roadmap |
| Teste de leitura falhando com `sudo: command not found` | Instalação mínima sem `sudo` | Usar `runuser -u zabbix --` ou `su -s /bin/sh zabbix -c` |
| Reboot pendente sempre -1 no Rocky | `needs-restarting` ausente | Instalar `yum-utils` |

## Números

| Problema | Causa | Solução |
|---|---|---|
| Total de CVEs muito acima do esperado | O total inclui CVEs sem patch | Indicador principal é a CVE corrigível |
| CVE corrigível que o `apt` não atualiza | Pacote órfão da versão anterior do sistema | Verificar `apt-cache policy` e dependência reversa, simular e remover |
| Contagem por pacote não fechando com o total | Achados UNKNOWN fora do ranking | Campo `unknown` incluído em `top_packages` |
| CVE corrigível ausente do ranking | `top_cves` guarda só 15 entradas ordenadas por severidade | Contadores numéricos completos e melhoria prevista no roadmap |
| Itens não suportados em hosts apt | Os campos de avisos não existem no JSON | Fallback -1 com value map `N/D (apt)` |

## Agente e cadastro

| Problema | Causa | Solução |
|---|---|---|
| Sem dados em um host que executa Zabbix proxy | `ServerActive` com dois endereços separados por vírgula, tratados como HA, com o próprio host primeiro | Apontar somente para o servidor que monitora o host |
| `host [X] not found` no log do agente | Nome técnico do host no Zabbix diferente do `Hostname` do agente ou configuração ainda não sincronizada | Igualar os nomes e aguardar a sincronização |

## Grafana

| Problema | Causa | Solução |
|---|---|---|
| Helper de parse que não registrava | Uso do objeto global `Handlebars` | Usar `context.handlebars.registerHelper`, conforme a documentação do plugin |
| Zabbix sem tabela para JSON | Nenhum widget do Zabbix interpreta JSON | Painel Business Text no Grafana |

## Regra prática

Antes de confiar em um número ou em um trecho de código, confira a origem. A estimativa de queda de CVEs únicas na limpeza de pacotes órfãos estava errada, porque os pacotes removidos eram pequenos. O helper do Grafana seguia uma API diferente da documentada. Os dois erros foram corrigidos ao comparar com dados reais e com a documentação oficial.
