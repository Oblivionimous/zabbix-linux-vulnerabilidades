# Template Linux vulnerabilidades no Zabbix

O template **Linux vulnerabilidades by Zabbix agent active** lê o relatório do coletor e cria indicadores, triggers e um dashboard por host. Importe [zabbix/template_linux_vulnerabilidades.yaml](../zabbix/template_linux_vulnerabilidades.yaml), no formato Zabbix `7.0`.

## Conteúdo

| Objeto | Quantidade |
|---|---|
| Item mestre de agente ativo | 1 |
| Itens dependentes | 24 |
| Triggers | 8 |
| Gráficos | 4 |
| Dashboard de host | 1, com três widgets |
| Macros | 6 |
| Value maps | 2 |

A [referência do template](referencia-template.md) apresenta chaves, JSONPaths, expressões, macros e widgets. Ela é gerada a partir do YAML versionado.

## Pré-requisitos

- Coletor instalado conforme [instalacao.md](instalacao.md), com relatório em `/var/lib/zabbix-vuln/report.json`.
- Zabbix Server 7.0 e host habilitado. Outras versões precisam de validação de importação.
- `zabbix-agent` ou `zabbix-agent2` com checks ativos e leitura do relatório.
- Comunicação com o servidor ou proxy responsável, normalmente na porta TCP `10051`.

O agente apenas lê o relatório. O timer systemd executa a varredura como root. Não é necessário criar UserParameter ou liberar execução privilegiada para `zabbix`.

## Configurar o agente

Confira `/etc/zabbix/zabbix_agentd.conf` ou `/etc/zabbix/zabbix_agent2.conf`, conforme o serviço instalado.

| Parâmetro | Configuração |
|---|---|
| `ServerActive` | Servidor ou proxy que entrega os checks ativos deste host |
| `Hostname` | Mesmo valor do campo técnico **Host name** no Zabbix |
| `Server` | Lista permitida para checks passivos. Não configura o destino dos checks ativos |

Exemplo com endereço reservado para documentação:

```ini
ServerActive=192.0.2.10:10051
Hostname=host-exemplo
```

Substitua os valores pelo destino e nome reais. Para hosts com proxy, configure o proxy responsável e confira **Monitored by** no frontend.

### Mais de um destino

No Zabbix 7.0, vírgulas separam instalações independentes. Pontos e vírgulas separam membros do mesmo cluster de alta disponibilidade ou grupo de proxies. Veja a [sintaxe oficial de ServerActive](https://www.zabbix.com/documentation/7.0/en/manual/appendix/config/zabbix_agentd#serveractive).

```ini
# Dois servidores independentes
ServerActive=192.0.2.10,192.0.2.20

# Membros do mesmo cluster de alta disponibilidade
ServerActive=192.0.2.10;192.0.2.20
```

Use a configuração da sua topologia. Não inclua o próprio host como destino se ele não entrega os checks ativos.

Após editar, reinicie somente o serviço instalado. Isso exige privilégios administrativos:

```bash
# Agente clássico
systemctl restart zabbix-agent
```

```bash
# Agent 2
systemctl restart zabbix-agent2
```

### Leitura do relatório

O coletor cria o diretório com `0755` e o arquivo com `0644`. Verifique a leitura como usuário `zabbix`:

```bash
runuser -u zabbix -- test -r /var/lib/zabbix-vuln/report.json && echo 'leitura OK'
jq '{timestamp, status, duration, pkgmgr_status: .pkgmgr.status, trivy_status: .trivy.status}' \
  /var/lib/zabbix-vuln/report.json
```

Com agent2, teste a chave localmente:

```bash
runuser -u zabbix -- zabbix_agent2 -t 'vfs.file.contents[/var/lib/zabbix-vuln/report.json]' | cut -c1-200
```

O teste local confirma leitura. Confira também a entrega dos checks ativos no frontend.

## Importar

1. Em **Data collection > Templates > Import**, selecione o YAML versionado.
2. Revise **Create new** e **Update existing** para os objetos desejados.
3. Mantenha **Delete missing** desmarcado na primeira importação ou quando preservar objetos locais.
4. Confira a prévia de alterações e confirme **Import**.
5. Localize o template em **Templates/Security**.

Antes de atualizar, exporte o template instalado. **Update existing** pode substituir personalizações. **Delete missing** pode remover objetos ausentes do arquivo. Revise as opções conforme o objetivo da atualização.

Preserve UUIDs para identificar objetos entre versões. O YAML usa LF e valores escalares textuais, conforme o validador do projeto. Veja a [importação oficial de templates](https://www.zabbix.com/documentation/7.0/en/manual/xml_export_import/templates).

## Vincular aos hosts

1. Em **Data collection > Hosts**, abra o host.
2. Confira **Host name**, status e **Monitored by**.
3. Em **Templates**, vincule **Linux vulnerabilidades by Zabbix agent active**.
4. Salve e aguarde a atualização dos checks ativos.

Para vários hosts, use **Mass update > Link templates**. Preserve os demais vínculos.

## Validar

Em **Monitoring > Latest data**, filtre pelo host e pela tag de item `template: linux-vulnerabilidades`.

<img width="2553" height="952" alt="image" src="https://github.com/user-attachments/assets/c408b6e0-c6d4-494b-ab59-57eb29799da9" />

Interface aproximada e tempos de check ilustrativos. Os nomes e valores seguem o template e o relatório de exemplo. A [galeria](galeria.md#zabbix-latest-data) descreve a origem dos dados.

| Item | Resultado esperado |
|---|---|
| `Vuln: status da coleta` | `ok`, com os componentes do relatório também verificados |
| `Vuln: horário da última coleta` | Data recente, comparada ao timestamp do arquivo |
| `Vuln: duração da coleta` | Segundos |
| `Vuln: relatório JSON` | Histórico desabilitado. Confira os valores pelos itens dependentes |
| Advisories e CVEs nativas em hosts apt | `-1`, exibido como `N/D (apt)` |
| Rankings de CVEs e pacotes | Listas JSON, possivelmente vazias quando não houver achados |

O primeiro recebimento pode levar até `30m`. Esse intervalo do item mestre é diferente da coleta diária.

Contadores e status descartam valores iguais com heartbeat de `6h`. Os rankings usam heartbeat de `1d`. Timestamp e duração são registrados a cada recebimento. A data no histórico pode ser anterior à última leitura do relatório.

Zero em uma contagem não comprova sucesso. Confira `vuln.scan.status`, timestamp e `.pkgmgr.status` e `.trivy.status` do relatório. Veja [troubleshooting.md](troubleshooting.md) para ausência de dados.

## Macros

Configure limites na aba **Macros** do host ou template. Macros de host prevalecem sobre as herdadas. Grupos de hosts não definem macros. Para vários hosts, use atualização em massa ou um template apropriado. Veja as [macros de usuário do Zabbix](https://www.zabbix.com/documentation/7.0/en/manual/config/macros/user_macros).

| Macro | Padrão | Uso |
|---|---|---|
| `{$VULN.OS.CRIT.MAX}` | `0` | Limite de Critical corrigíveis em pacotes do SO |
| `{$VULN.OS.HIGH.MAX}` | `0` | Limite de High corrigíveis em pacotes do SO |
| `{$VULN.LANG.CRIT.MAX}` | `0` | Limite de Critical corrigíveis em aplicações |
| `{$VULN.PATCH.MAX.DAYS}` | `60` | Dias desde a instalação de pacote antes do alerta informativo |
| `{$VULN.REBOOT.MAX}` | `7d` | Janela de `min()` para verificar reboot pendente |
| `{$VULN.SCAN.MAX.AGE}` | `36h` | Idade máxima do relatório |

As expressões de CVE usam `>`, não `>=`. Com limite `0`, uma CVE corrigível supera o limite.

## Triggers e ações

| Condição | Prioridade | Tag scope |
|---|---|---|
| Status diferente de `ok` | Atenção | `availability` |
| Relatório acima de `{$VULN.SCAN.MAX.AGE}` | Atenção | `availability` |
| Critical corrigível em SO acima do limite | Alta | `security` |
| High corrigíveis em SO acima do limite | Média | `security` |
| Critical corrigível em aplicações acima do limite | Média | `security` |
| Advisory Critical pendente | Alta | `security` |
| Reboot pendente em todas as amostras da janela | Atenção | `configuration` |
| Dias desde instalação de pacote acima do limite | Informação | `configuration` |

A trigger de reboot usa `min(item, janela)=1`. Ela examina amostras existentes, sem armazenar a data inicial da pendência. Um host recém-vinculado pode ter histórico menor que sete dias. Considere esse limite ao interpretar o alerta.

A trigger de relatório antigo calcula `now()-last(timestamp)`. Ela não substitui `nodata()` para um host que nunca enviou dados.

As triggers de CVE usam contadores corrigíveis. A de advisory usa a informação da distribuição. Ausência de versão corrigida no Trivy não significa ausência de risco ou mitigação.

O template não inclui ações. Configure-as em **Alerts > Actions > Trigger actions**. Uma condição `scope: security` cobre quatro triggers. Ela não cobre falhas de coleta ou pendências de configuração.

As expressões completas estão na [referência](referencia-template.md). Os procedimentos estão em [operacao.md](operacao.md).

## Dashboard nativo do host

Em **Monitoring > Hosts > Dashboards**, selecione **Vulnerabilidades - visão geral**. A página **Situação atual** contém:

- Problemas abertos com `scope: security`.
- Gráfico de corrigíveis por severidade.
- Gráfico de corrigíveis Critical e High em SO e aplicações.

<img width="2553" height="950" alt="image" src="https://github.com/user-attachments/assets/4d190aeb-9b99-4114-8b4e-27bc19c7ec8f" />

Prévia ilustrativa, com dados de exemplo e histórico fictício. O layout do frontend é aproximado. Veja a [origem da imagem](galeria.md#zabbix-dashboard-do-host).

O widget de problemas não mostra `availability` e `configuration`. Consulte a lista geral de problemas para acompanhar coleta e reboot.

O template não inclui tabelas que decodifiquem rankings JSON. O [dashboard Grafana](grafana.md) mostra os rankings e consolida hosts. Ele é importado separadamente e é opcional para a coleta.

## Limites de interpretação

- Corrigível significa `FixedVersion` em pelo menos um achado agregado. Confira pacote e versão antes de planejar a atualização.
- A idade da CVE usa a publicação, não a data do patch.
- `last_patch_days` mede instalação de qualquer pacote.
- Rankings têm até quinze entradas por host. Contadores não têm esse limite.
- SO e aplicação podem conter a mesma CVE. Os conjuntos não são exclusivos.
- `-1` indica dado indisponível. Não trate como quantidade negativa.

Veja o relatório e a agregação em [arquitetura.md](arquitetura.md).
