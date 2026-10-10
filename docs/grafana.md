# Dashboard de vulnerabilidades no Grafana

O **Dashboard de Vulnerabilidades - Visão Geral** reúne os indicadores dos hosts Linux em um painel Business Text. Ele usa os itens do [template Zabbix](zabbix.md), com filtros por host, CVE e pacote.

Importe [grafana/dashboard_linux_vulnerabilidades.v2.json](../grafana/dashboard_linux_vulnerabilidades.v2.json). O JSON contém consultas, JavaScript, CSS e layout. Não é necessário montar cada tabela manualmente.

A [galeria da integração](galeria.md) reúne a prévia do painel, exemplos de telas Zabbix e o fluxo de coleta. Todas as prévias têm a origem identificada.

## Compatibilidade e validação

| Componente | Evidência do export fornecido |
|---|---|
| Grafana | `13.2.3`, registrado nos metadados de origem |
| Modelo do dashboard | `dashboard.grafana.app/v2`, formato V2 Resource |
| Business Text | `marcusolsson-dynamictext-panel` `6.3.0` |
| Fonte de dados | `alexanderzobnin-zabbix-datasource`. A versão do plugin Zabbix não consta no export |
| Zabbix | Template exportado no formato `7.0` |

Esses dados identificam o ambiente de origem. Não comprovam compatibilidade com todas as versões. A importação e as consultas precisam ser verificadas na instância de destino.

Use uma instância Grafana que aceite V2 Resource e o Business Text 6.3.0 para reproduzir o export. Confira os requisitos do plugin Zabbix escolhido no [catálogo oficial](https://grafana.com/grafana/plugins/alexanderzobnin-zabbix-app/).

Para uma instância que exija Classic, reexporte o dashboard pelo Grafana com esse modelo. Remover `apiVersion` ou renomear `spec` não converte o V2. Veja a [documentação dos modelos JSON](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/view-dashboard-json-model/).

## Recursos do painel

- Índice de saúde por host e média dos hosts selecionados.
- Contagens e evolução das CVEs corrigíveis Critical, High e Medium.
- Total de CVEs únicas, proporção com correção, pendência mais antiga e reboots pendentes.
- Comparação entre pacotes do sistema operacional e bibliotecas de aplicações.
- Ranking de hosts, tabela de CVEs, blocos de pacotes e mapa de calor.
- Pontos de atenção calculados pelo próprio painel.

## Preparar a fonte de dados

1. Instale e habilite o app Zabbix, identificado por `alexanderzobnin-zabbix-app`.
2. Instale o painel Business Text, identificado por `marcusolsson-dynamictext-panel`.
3. Em **Connections > Data sources**, crie ou selecione a fonte Zabbix.
4. Configure a URL da API, por exemplo `https://zabbix.example.com/api_jsonrpc.php`. Inclua o subdiretório do frontend, se houver.
5. Configure a autenticação na fonte. A conta Zabbix precisa ler os hosts e grupos monitorados.
6. Execute **Save & test** e confirme a versão da API retornada.
7. Copie o UID da fonte. Ele identifica a conexão no JSON e não é uma credencial.

O plugin instalado usa o ID `alexanderzobnin-zabbix-app`. As consultas usam `alexanderzobnin-zabbix-datasource`. Veja a [configuração oficial da fonte Zabbix](https://grafana.com/docs/plugins/alexanderzobnin-zabbix-app/latest/configure/).

## Importar o dashboard

1. Faça uma cópia de `grafana/dashboard_linux_vulnerabilidades.v2.json`.
2. Substitua as duas ocorrências de `ZABBIX_DATASOURCE_UID` pelo UID da sua fonte Zabbix.
3. Em **Dashboards > New > Import dashboard**, envie essa cópia.
4. Escolha a pasta e revise o identificador proposto antes de confirmar a importação.
5. Abra o painel em modo de edição e confira a fonte nas consultas A e B.
6. Restrinja os filtros de grupo e host ao escopo desejado. O arquivo usa `/.*/` para ambos.
7. Salve e confirme os valores em **Inspect > Data**.

O nome de recurso é `linux-vulnerabilidades-visao-geral`. Confira conflitos antes de importar uma segunda cópia. Veja o [procedimento oficial de importação](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/import-dashboards/).

O JSON publicado remove identificadores de usuário, UID interno e metadados de revisão da origem. A fonte recebe um marcador explícito. Configure as credenciais somente no Grafana.

## Consultas e atualização

As consultas precisam retornar os mesmos hosts.

| Consulta | Modo | Filtro de item |
|---|---|---|
| A | Metrics, `queryType: "0"` | `/^Vuln: .*/` |
| B | Text, `queryType: "2"` | `/^Vuln: (ranking de CVEs\|ranking de pacotes\|status da coleta)$/` |

A consulta A fornece contagens, datas, duração e flags numéricas. A consulta B fornece status e rankings JSON. Mantenha `useZabbixValueMapping: false` para o código receber valores originais.

O código reconhece séries como `host-exemplo: Vuln: CVEs corrigíveis CRITICAL`. Também aceita labels `host` e `item`, ou campos tabulares de host e item. Não configure aliases que removam essas informações.

Os rankings vêm de `vuln.rank.cves` e `vuln.rank.packages`. O código usa `JSON.parse` e seleciona a amostra mais recente disponível no período.

O arquivo abre nas últimas `48h`, com atualização de `5m` e fuso `browser`. A janela inclui os heartbeats de `6h` dos contadores e status e de `1d` dos rankings.

- O coletor executa diariamente pelo timer systemd.
- O item mestre Zabbix lê o relatório a cada `30m`.
- O Grafana atualiza as consultas a cada `5m`.

Atualizar o dashboard não executa outra varredura. Aumente a janela se faltarem amostras. O histórico dos rankings dura `7d`.

## Filtros

- **Escopo:** seleciona todos os hosts ou um host. Quadrados dos hosts e nomes de hosts também alteram a seleção.
- **Filtrar por CVE ou pacote:** restringe a tabela de CVEs e os blocos de pacotes. Não recalcula os indicadores gerais.
- **Só corrigíveis:** restringe a tabela de CVEs. Não filtra os pacotes nem os contadores.
- **Legenda do gráfico:** mostra ou oculta cada série.

O quadro de hosts e o mapa de calor continuam mostrando todos os hosts retornados. A seleção de host altera cartões, exposição, composição, rankings e pontos de atenção.

**Última coleta** mostra a maior data entre todos os hosts retornados. Confira também a data de cada host no mapa de calor.

## Interpretar os números

| Indicador | Significado e limite |
|---|---|
| CVEs únicas, todos os hosts | Soma das CVEs únicas por host. A mesma CVE em dois hosts conta duas vezes |
| Corrigíveis | CVEs com `FixedVersion` em pelo menos um achado. Não garante correção em todos os pacotes ou hosts |
| Tabela de CVEs | Agrupa os rankings por identificador e mostra até dez CVEs após os filtros |
| Pacotes com mais CVEs | Soma os achados dos rankings por pacote e mostra até doze pacotes. Não deduplica entre pacotes |
| Pendência mais antiga | Maior idade desde a publicação de uma CVE Critical ou High corrigível. Não mede a data do patch |
| Último pacote | Dias desde a instalação de qualquer pacote, inclusive sem relação com segurança |

O coletor envia até quinze CVEs e quinze pacotes por host. Os rankings consolidados não são um inventário completo. Os contadores consideram todos os achados após o filtro de kernels antigos.

Na tabela consolidada, **Corrigível** vale quando pelo menos um host do ranking informa correção. SO e aplicação podem conter a mesma CVE. Evite somá-los como conjuntos exclusivos.

O bloco **Medium e Low** calcula o restante após retirar Critical e High, incluindo UNKNOWN. O total corrigível soma Critical, High, Medium e Low. O template não expõe um contador corrigível UNKNOWN.

Algumas células mostram `N/D`, mas somas e índice tratam várias ausências como zero. Hosts sem séries não aparecem. Índice alto ou estado visual `ok` não comprova coleta íntegra quando faltam timestamp, status ou contadores.

A evolução mantém o último valor disponível de cada host dentro das séries recebidas. Antes da primeira amostra, o cálculo pode usar zero. Verifique a cobertura do período antes de interpretar aumentos e quedas.

## Índice de saúde

O índice é uma regra local de apresentação. Não é CVSS, percentual de proteção ou trigger do Zabbix.

```text
índice = max(0, round(100
  - min(40, Critical_corrigíveis * 20)
  - min(35, High_corrigíveis * 1,5)
  - min(10, Medium_corrigíveis * 0,3)
  - 10 se coleta com mais de 36h
  - 5 se reboot pendente
  - 20 se status da coleta diferente de ok))
```

A cor usa verde a partir de 90, amarelo de 70 a 89 e vermelho abaixo de 70. Na seleção de vários hosts, o índice é a média aritmética arredondada.

Os níveis dos hosts seguem outra regra:

- **Crítico:** qualquer Critical corrigível ou erro de coleta.
- **Atenção:** qualquer High corrigível, coleta atrasada, reboot pendente ou mais de 60 dias desde a instalação de pacote.
- **Normal:** nenhuma dessas condições foi identificada nos dados recebidos.

Os pontos de atenção incluem também idade da CVE acima de 90 dias e achados de kernels antigos descartados. Esses dois casos não alteram o nível do host.

Os limites `36h`, `60 dias` e `90 dias` ficam no JavaScript. O painel não lê macros Zabbix. Alterar uma macro pode produzir uma trigger diferente do ponto de atenção mostrado.

## Manutenção

O JSON é o artefato importável. Estes arquivos reproduzem o conteúdo do painel para revisão no GitHub:

| Arquivo | Campo do Business Text |
|---|---|
| [business-text-content.html](../grafana/business-text-content.html) | Content |
| [business-text-after-render.js](../grafana/business-text-after-render.js) | JavaScript > After Content Ready |
| [business-text-styles.css](../grafana/business-text-styles.css) | Styles |

Mantenha **Render template = All data**, correspondente a `renderMode: "data"`. O código usa `context.element` e as séries de `context.panel.panelData` ou `context.panelData`. Veja os [modos de renderização](https://grafana.com/docs/plugins/marcusolsson-dynamictext-panel/latest/rendering/).

**Before Content Rendering** fica vazio. O painel monta HTML em After Content Ready, sem helpers Handlebars. Veja o [contexto JavaScript do plugin](https://grafana.com/docs/plugins/marcusolsson-dynamictext-panel/latest/javascript-code/).

Ao alterar JavaScript, CSS ou Content, atualize o campo correspondente no JSON. Preserve os nomes dos itens Zabbix, usados para identificar métricas.

Os filtros ficam em `window.__vulnvz`. Múltiplas cópias do painel na mesma página podem compartilhar esse estado. Valide esse cenário antes de duplicar o painel.

## Validação na instância de destino

1. Compare um host em **Monitoring > Latest data** com o mesmo host no dashboard.
2. Confira Critical, High, CVEs únicas, timestamp, status e reboot.
3. Confira os rankings e a amostra mais recente em **Inspect > Data**.
4. Teste seleção de host, busca, Só corrigíveis e legenda do gráfico.
5. Verifique que o quadro de hosts e o mapa de calor mantêm o escopo geral.
6. Aguarde uma atualização e confira erros no console do navegador.
7. Confira um host com coleta atrasada ou erro antes do uso operacional.

Uma prévia com dados simulados verifica renderização e interação. Ela não testa API Zabbix, autenticação ou importação V2.

## Solução de problemas

| Sintoma | Verificação |
|---|---|
| Fonte não encontrada | Substituir o marcador nas duas consultas pelo UID correto |
| Plugin não encontrado | Instalação e habilitação do app Zabbix e instalação do Business Text |
| Sem dados | Filtros, período, permissões da conta e valores em Latest data |
| Números sem rankings | Consulta B em Text e histórico dentro do período |
| Hosts não reconhecidos | Nome `host: Vuln: item` ou labels/campos equivalentes |
| Ranking corrigível vazio | O ranking limitado pode não conter as corrigíveis dos contadores |
| Exibição parcial | Versão do plugin, campo After Content Ready e console do navegador |
| JSON V2 rejeitado | Instância compatível ou reexportação em Classic pelo Grafana |

Não desative a sanitização global como primeiro ajuste. Confira execução e configuração do plugin antes de alterar controles globais.

## Prévia

![Prévia do painel com dados simulados](assets/grafana-exemplo.png)

Prévia local com dados simulados derivados de `examples/report.example.json`. Não representa uma instância Grafana nem dados de produção.
