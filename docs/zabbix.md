# Configuração no Zabbix

## Agente

O item mestre é do tipo agente ativo e usa a chave `vfs.file.contents`, que existe no `zabbix-agent` e no `zabbix-agent2`. Três parâmetros do arquivo de configuração do agente precisam estar corretos.

| Parâmetro | Exigência |
|---|---|
| `ServerActive` | Endereço do servidor Zabbix que recebe os dados ativos |
| `Hostname` | Idêntico, letra por letra, ao nome técnico do host cadastrado no frontend |
| `Server` | Continua valendo para checks passivos e não interfere nesta solução |

Os arquivos ficam em `/etc/zabbix/zabbix_agent2.conf` ou `/etc/zabbix/zabbix_agentd.conf`, conforme o agente.

### Cuidado com vários endereços em ServerActive

Endereços separados por vírgula em `ServerActive` são tratados como nós de um mesmo cluster de alta disponibilidade. Para enviar dados a dois servidores independentes, separe-os com ponto e vírgula.

```
ServerActive=192.0.2.10;192.0.2.20
```

Em um host que executa o Zabbix proxy, um `ServerActive` com o próprio endereço na primeira posição fez o agente tentar a porta 10051 local. O log registrou `Active check configuration update started to fail`. Aponte apenas para o servidor que monitora o host.

Depois de alterar o arquivo, reinicie o agente.

```bash
systemctl restart zabbix-agent
```

Em hosts com agent2, use `zabbix-agent2`.

### Permissão de leitura

O agente roda como o usuário `zabbix` e precisa ler `/var/lib/zabbix-vuln/report.json`. O script cria o arquivo com permissão `0644` e o diretório com `0755`. Para testar sem `sudo`.

```bash
runuser -u zabbix -- cat /var/lib/zabbix-vuln/report.json > /dev/null && echo "leitura OK"
```

### Teste local da chave

Com o agent2, a chave pode ser testada direto no host.

```bash
runuser -u zabbix -- zabbix_agent2 -t 'vfs.file.contents[/var/lib/zabbix-vuln/report.json]' | cut -c1-200
```

## Importar o template

1. Em Data collection > Templates, clique em Import.
2. Selecione `zabbix/template_linux_vulnerabilidades.yaml`.
3. Marque Create new e Update existing. Marque Delete missing somente se quiser remover itens antigos que não existem mais no arquivo.
4. Clique em Import.

O arquivo deve usar quebra de linha LF. O repositório força isso pelo `.gitattributes`. Se o importador reclamar de estrutura, veja [troubleshooting.md](troubleshooting.md).

## Vincular a um host

1. Em Data collection > Hosts, abra o host. O campo Host name deve ser igual ao `Hostname` do agente.
2. Em Templates, vincule `Linux vulnerabilidades by Zabbix agent active`.
3. Confirme que o campo Monitored by aponta para o servidor ou proxy correto.

Para muitos hosts, selecione-os na lista, escolha Mass update e use Link templates.

## Validar

Em Monitoring > Latest data, filtre pelo host e adicione o filtro de tag `template` igual a `linux-vulnerabilidades`. Todos os itens do template aparecem.

| Item | Resultado esperado |
|---|---|
| Vuln: status da coleta | `ok` |
| Vuln: horário da última coleta | Data recente |
| Vuln: relatório JSON | Sem valor. O item mestre não guarda histórico |
| Itens de avisos em hosts com apt | `N/D (apt)` |

O primeiro valor pode levar até 30 minutos, que é o intervalo do item mestre.

## Macros

Ajuste as macros no host ou em um grupo de hosts para adequar limites à criticidade do servidor.

| Macro | Padrão | Efeito |
|---|---|---|
| `{$VULN.OS.CRIT.MAX}` | 0 | Limite de CVEs CRITICAL corrigíveis em pacotes do SO |
| `{$VULN.OS.HIGH.MAX}` | 0 | Limite de CVEs HIGH corrigíveis em pacotes do SO |
| `{$VULN.LANG.CRIT.MAX}` | 0 | Limite de CVEs CRITICAL corrigíveis em aplicações |
| `{$VULN.PATCH.MAX.DAYS}` | 60 | Dias sem instalar pacote antes do alerta informativo |
| `{$VULN.REBOOT.MAX}` | 7d | Tempo máximo com reboot pendente |
| `{$VULN.SCAN.MAX.AGE}` | 36h | Idade máxima do relatório |

## Triggers

Os textos completos e as expressões estão em [referencia-template.md](referencia-template.md). O que fazer quando cada uma dispara está em [operacao.md](operacao.md).

As triggers de CVE usam somente CVEs corrigíveis. Um host com muitas CVEs sem patch não gera alerta, porque não existe ação possível.

## Dashboard do host

O template inclui o dashboard "Vulnerabilidades - visão geral". Ele aparece em Monitoring > Hosts, coluna Dashboards. Mostra os problemas abertos com a tag `scope: security` e dois gráficos de CVEs corrigíveis.

Este dashboard não usa cartões de valor único. Se quiser, adicione widgets do tipo Item value pela interface.

## Notificação

O template cria triggers, mas não cria ações. Para receber avisos, configure uma ação em Alerts > Actions com a condição de tag `scope` igual a `security`. Veja o [roadmap](roadmap.md).
