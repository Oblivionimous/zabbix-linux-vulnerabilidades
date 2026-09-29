# Grafana

Os itens `Vuln: ranking de CVEs` e `Vuln: ranking de pacotes` guardam listas em JSON. O Zabbix não transforma esse texto em tabela, porque nenhum widget de dashboard do Zabbix interpreta JSON. O Grafana faz isso com o painel Business Text (plugin `marcusolsson-dynamictext-panel`).

Os indicadores numéricos, como CVEs corrigíveis por severidade, não precisam de tratamento. Use painéis nativos (Stat, Bar gauge, Time series) sobre os itens `vuln.trivy.*`.

## Estado de validação

Os arquivos desta pasta seguem a documentação oficial do plugin, versão 6.x. Eles ainda não foram testados de ponta a ponta em uma instância Grafana com a fonte de dados Zabbix. Dois pontos podem exigir ajuste.

- O nome do campo que a fonte de dados Zabbix devolve para o valor do item de texto. Os modelos assumem `Value`.
- O tipo de consulta da fonte de dados, que deve retornar o último valor do item de texto.

Abra Inspect > Data no painel para ver o nome real do campo.

## Requisitos

- Grafana com o plugin `marcusolsson-dynamictext-panel` (Business Text).
- Fonte de dados `alexanderzobnin-zabbix-datasource` apontada para o Zabbix.
- Nos hosts, o template importado e coletando.

## Tabela de ranking de CVEs

1. Crie um painel do tipo Business Text.
2. Na consulta, selecione o host e o item `Vuln: ranking de CVEs`.
3. Em Render template escolha `All rows`.
4. Em JavaScript > Before Content Rendering cole o conteúdo de `grafana/business-text-helper.js`.
5. Em Content cole o conteúdo de `grafana/business-text-cves.hbs`.

O helper `parseJSON` converte o texto do item em uma lista. O modelo percorre a lista com `{{#each}}` e monta a tabela HTML.

## Tabela de ranking de pacotes

Repita os passos com o item `Vuln: ranking de pacotes` e o arquivo `grafana/business-text-pacotes.hbs`.

## Detalhes do plugin que importam

- Helpers devem ser registrados em Before Content Rendering, porque o Handlebars não está disponível em After Content Ready.
- O registro usa `context.handlebars.registerHelper`. O uso do objeto global `Handlebars` não segue a documentação.
- O plugin sanitiza o HTML por padrão, então estilos e atributos inline podem ser removidos conforme a configuração do Grafana.

## Gráfico de barras

Um gráfico horizontal de pacotes com o painel `volkovlabs-echarts-panel` está no [roadmap](roadmap.md). A sintaxe de consulta e de opções desse painel ainda não foi validada.
