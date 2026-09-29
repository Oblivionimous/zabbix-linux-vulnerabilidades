# Solução de problemas

## Dados não chegam ao Zabbix

| Sintoma | Causa provável | Verificação |
|---|---|---|
| `Active check configuration update started to fail` no log do agente | O agente não consegue buscar a lista de checks ativos | Conferir `ServerActive` e a conectividade com a porta 10051 |
| `no active checks on server ... host [X] not found` | O nome técnico do host no Zabbix não coincide com o `Hostname` do agente | Comparar os dois valores, incluindo maiúsculas e espaços. Aguardar a sincronização da configuração do servidor |
| `cannot connect to [[IP]:10051]: connection error` | Porta bloqueada ou o endereço aponta para o próprio host | Testar com `timeout 3 bash -c 'cat < /dev/null > /dev/tcp/IP/10051'` |
| Item mestre sem última checagem | Agente em modo passivo ou host sem template | Conferir o vínculo do template e o `ServerActive` |
| Itens dependentes não suportados com `cannot extract value from json by path` | O campo não existe no JSON deste host | Em hosts apt, os itens de avisos usam fallback -1. Reimporte o template atual |

Comandos úteis no host.

```bash
tail -60 /var/log/zabbix/zabbix_agent2.log | grep -iE "active check|failed|refused|not found"
grep -E '^(Server|ServerActive|Hostname)=' /etc/zabbix/zabbix_agent*.conf
```

Em agente clássico o log é `/var/log/zabbix/zabbix_agentd.log`.

## Coleta

| Sintoma | Causa provável | Correção |
|---|---|---|
| `status: error` no relatório | Falha do gerenciador de pacotes ou do trivy | Ver `.pkgmgr.error` e `.trivy.error` no JSON |
| `.trivy.status` igual a `not_installed` | trivy fora do PATH do root | Instalar o trivy e conferir `command -v trivy` |
| Coleta muito lenta | Trivy percorrendo storage grande | Adicionar o diretório em `/etc/zabbix-vuln/extra-skip-dirs` |
| Serviço encerrado por memória | Estouro de `MemoryMax` | Aumentar o limite no service |
| Primeira execução demorada | Download da base de vulnerabilidades | Esperado. As seguintes são mais rápidas |
| Falha ao baixar a base | Sem saída HTTPS para os registros do trivy | Liberar a saída ou usar um espelho interno, veja o [roadmap](roadmap.md) |
| `Could not resolve host: pkg.aquasec.com` no dnf | Repositório do trivy configurado e sem DNS | Remover o arquivo `.repo` e instalar pelo pacote da release |

## Números inesperados

| Situação | Explicação |
|---|---|
| Milhares de achados em kernel | Kernels antigos instalados. O filtro os descarta. Se aparecerem no ranking, confira os prefixos de nome de pacote |
| CVEs corrigíveis que o gerenciador não atualiza | Pacote órfão de versão anterior do sistema, veja [sistemas-operacionais.md](sistemas-operacionais.md) |
| Muitas CVEs únicas e zero corrigíveis | Nenhum fornecedor publicou patch. Veja "Como interpretar os números" em [arquitetura.md](arquitetura.md) |
| `-1` nos itens de avisos | Host com apt. O dado não existe nessa distribuição |
| CVE corrigível fora do ranking | O ranking guarda só 15 CVEs. Os contadores numéricos não têm esse limite |

Para ver todas as CVEs corrigíveis de um host, incluindo as fora do ranking.

```bash
trivy rootfs --scanners vuln -q --format json / \
  | jq -r '.Results[]?.Vulnerabilities[]? | select(.FixedVersion != null and .FixedVersion != "")
           | "\(.Severity) \(.VulnerabilityID) \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion)"' | sort
```

Esse comando não aplica o filtro de kernel antigo do script. Kernels não carregados podem aparecer na saída.
