# Galeria da integração

A galeria reúne capturas de testes reais do Zabbix 7.0.31, uma prévia local do painel Grafana e ilustrações da coleta. A tabela identifica a origem de cada imagem.

| Imagem | Origem |
|---|---|
| Grafana | Código do painel Business Text executado localmente com dados simulados |
| Zabbix: dashboard do host | Captura de teste real no ambiente Zabbix Testes, no host Zabbix server |
| Zabbix: Latest data | Captura de teste real com 25 itens: um mestre e 24 dependentes |
| Coleta e relatório | Comandos de leitura com saídas ilustrativas e recorte do relatório de exemplo |
| Fluxo de coleta | Diagrama baseado nos scripts, template e dashboard versionados |

## Grafana

![Prévia local do dashboard Grafana com dados simulados, indicadores dos hosts, rankings e mapa de calor](assets/grafana-exemplo.png)

O código do painel Business Text foi executado localmente com dois hosts simulados. A prévia usa dados derivados de `examples/report.example.json`. Consulte [grafana.md](grafana.md) para configurar a fonte de dados e importar o dashboard.

## Zabbix: dashboard do host

<img width="2552" height="946" alt="Dashboard do host Zabbix server no ambiente Zabbix Testes, com problemas e gráficos de dados reais da coleta" src="https://github.com/user-attachments/assets/3eb7d27b-69ea-4859-9f10-bd486490fb43" />

A captura mostra um teste real no **Zabbix 7.0.31**, no ambiente **Zabbix Testes**, para o host **Zabbix server**. Os valores e o histórico correspondem ao momento da captura.

Os nomes e a disposição dos três widgets seguem [template_linux_vulnerabilidades.yaml](../zabbix/template_linux_vulnerabilidades.yaml): um widget de problemas com `scope: security` e dois gráficos.

Consulte [zabbix.md](zabbix.md) para importação, vínculo, macros e interpretação. A documentação oficial do Zabbix 7.0 descreve os widgets [Problems](https://www.zabbix.com/documentation/7.0/en/manual/web_interface/frontend_sections/dashboards/widgets/problems) e [Graph](https://www.zabbix.com/documentation/7.0/en/manual/web_interface/frontend_sections/dashboards/widgets/graph).

## Zabbix: Latest data

<img width="2541" height="950" alt="Latest data do host Zabbix server em teste real, mostrando os 25 itens do template: um mestre e 24 dependentes" src="https://github.com/user-attachments/assets/79b7fe28-417f-4bef-89a5-daea5c1cbab2" />

A captura de teste real mostra os **25 itens do template: um item mestre e 24 dependentes**. O item mestre lê o relatório JSON. Os dependentes extraem seus valores pelos respectivos JSONPaths. O frontend apresenta as datas conforme seu fuso configurado. O value map de reboot converte `0` em `Não` e `1` em `Sim`.

O intervalo de leitura do item mestre é `30m`, mas itens com descarte de valores iguais podem ter um horário anterior no histórico. Consulte a [documentação oficial de Latest data](https://www.zabbix.com/documentation/7.0/en/manual/web_interface/frontend_sections/monitoring/latest_data) e o procedimento de [validação](zabbix.md#validar).

## Coleta e relatório

![Prévia ilustrativa de comandos de leitura no Linux e de um recorte do relatório JSON, com os status dos componentes e os contadores do exemplo](assets/coleta-relatorio-exemplo.png)

Esta imagem é ilustrativa. As saídas dos comandos foram preparadas para demonstrar as verificações. Os valores do JSON vêm de `examples/report.example.json`.

Os comandos mostrados consultam estado, relatório e permissões. Consulte [operacao.md](operacao.md) para executar as verificações no host real e [instalacao.md](instalacao.md) para instalar o coletor.

## Fluxo de coleta

![Diagrama do fluxo: coleta diária como root no Linux, relatório JSON, agente ativo com leitura a cada trinta minutos, Zabbix com itens dependentes e Grafana com refresh a cada cinco minutos](assets/fluxo-coleta.svg)

O diagrama diferencia as três frequências. A atualização do Grafana não executa a varredura novamente. Os limites de CPU, memória e IO aplicam-se ao service de coleta. Consulte [arquitetura.md](arquitetura.md).
