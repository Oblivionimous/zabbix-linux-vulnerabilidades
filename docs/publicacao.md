# Preparar a publicação no GitHub

O repositório distribui dois artefatos independentes: o template YAML do Zabbix e o dashboard JSON V2 do Grafana. A documentação explica instalação, configuração e limites de interpretação.

## Arquivos da publicação

| Arquivo | Finalidade |
|---|---|
| [Template Zabbix](../zabbix/template_linux_vulnerabilidades.yaml) | Importação em Zabbix 7.0 |
| [Dashboard Grafana V2](../grafana/dashboard_linux_vulnerabilidades.v2.json) | Importação após configurar o UID da fonte |
| [Guia Zabbix](zabbix.md) | Agente, importação, vínculo, macros, triggers e validação |
| [Guia Grafana](grafana.md) | Plugins, consultas, filtros, índice e limitações |
| [Referência gerada](referencia-template.md) | Inventário e configuração extraídos do YAML |

Os arquivos `grafana/business-text-*` reproduzem Content, JavaScript e CSS do JSON para facilitar revisão. A captura em `docs/assets/grafana-exemplo.png` usa dados simulados e deve manter essa identificação.

## Revisar exports

1. Preserve UUIDs, chaves e nomes de itens do template Zabbix.
2. Gere novamente a referência quando alterar o YAML.
3. Mantenha `ZABBIX_DATASOURCE_UID` nas duas consultas do JSON publicado.
4. Remova metadados internos de usuário, revisão e instância de novos exports Grafana.
5. Confira se os arquivos Business Text correspondem aos campos do JSON.
6. Revise capturas, exemplos e logs antes de publicar informações de infraestrutura.
7. Identifique as versões registradas no export e as versões efetivamente testadas.

O export de origem registra Grafana 13.2.3 e Business Text 6.3.0. A versão do plugin Zabbix não está registrada. O modelo permanece V2 Resource. Para distribuir também Classic, gere esse export pelo Grafana e valide-o separadamente.

## Executar verificações

Execute na raiz do repositório, em Linux, conforme os testes existentes:

```bash
python3 -m pip install pyyaml
python3 tests/validate_template.py
python3 -m unittest discover -s tests -v
python3 tests/gerar_referencia.py
git diff --exit-code -- docs/referencia-template.md
git diff --check
```

Se a referência mudou intencionalmente, inclua o arquivo regenerado no commit e repita a verificação de consistência. Os testes do coletor usam `os.uname()` e um executável shell simulado. A execução direta desses testes requer Linux.

Confira também:

- Links relativos e captura de exemplo presentes no repositório.
- JSON válido e duas ocorrências do marcador de fonte.
- Ausência de identificadores da instância original no dashboard publicado.
- Importação Zabbix e Grafana em um ambiente de destino.
- Valores de um host comparados entre relatório, Latest data e Grafana.

A validação estrutural não comprova importação. A prévia local não testa autenticação, API ou entrega de checks ativos.

## Preparar o commit

Revise `git status` e `git diff` antes de selecionar arquivos. Inclua somente as alterações que pretende publicar. O exemplo abaixo cria uma branch de documentação e prepara os arquivos relacionados:

```bash
git switch -c codex/documentacao-template-dashboard
git add README.md CHANGELOG.md CONTRIBUTING.md docs/ grafana/ \
  zabbix/template_linux_vulnerabilidades.yaml tests/gerar_referencia.py
git diff --cached --check
git diff --cached --stat
git commit -m "docs: documenta template Zabbix e dashboard Grafana"
```

Se `docs/` contiver alterações anteriores de outro trabalho, selecione os arquivos individualmente. O commit registra alterações locais. O envio ao GitHub é uma etapa posterior, após revisar o conteúdo e os resultados do workflow.

Mantenha a seção **Não publicado** do changelog até definir uma release. Não atribua uma versão ou data de publicação antes da publicação efetiva.
