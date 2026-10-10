# Como contribuir

## Regras do projeto

- O script `src/vuln-collect.py` é idêntico em todos os hosts. Diferenças por host ficam em `/etc/zabbix-vuln/extra-skip-dirs`.
- Toda alteração no script muda o hash. Registre o novo hash no `CHANGELOG.md` e em `docs/operacao.md`.
- Arquivos usam quebra de linha LF. O `.gitattributes` força isso.
- Todo valor escalar do YAML do template deve estar entre aspas.
- Os identificadores UUID do template não devem mudar entre versões, para que a reimportação atualize os objetos existentes.

## Antes de abrir um pull request

```bash
pip install pyyaml
python3 tests/validate_template.py
python3 -m unittest discover -s tests -v
python3 tests/gerar_referencia.py
git diff --stat docs/referencia-template.md
```

Se o template mudou, `docs/referencia-template.md` deve ser regenerado e incluído no commit.

## Documentação e exports

- Use os nomes e chaves do YAML versionado para documentar o template.
- Diferencie versão registrada no export, validação estrutural e teste em uma instância real.
- Preserve os UUIDs do Zabbix e o formato V2 do dashboard Grafana.
- Ao alterar os arquivos `grafana/business-text-*`, atualize também os campos correspondentes no JSON importável.
- Mantenha `ZABBIX_DATASOURCE_UID` nas duas consultas do arquivo publicado. Configure o UID real somente na cópia local de importação.
- Remova metadados de usuário, revisão e instância antes de versionar um export.
- Não inclua credenciais, dados de produção ou capturas sem revisão. Identifique dados simulados nas prévias.
- Revise links relativos e instruções de importação em [docs/zabbix.md](docs/zabbix.md) e [docs/grafana.md](docs/grafana.md).

## Versionamento

O projeto segue SemVer. Mudanças no formato do `report.json` que removem campos exigem versão maior. A versão do template Zabbix no bloco `vendor` acompanha a versão suportada do Zabbix.

## Acrescentar suporte a uma distribuição

1. Identifique como a distribuição nomeia os pacotes de kernel e acrescente o prefixo em `stale_kernel`.
2. Acrescente casos em `tests/test_collect.py`.
3. Documente as particularidades em `docs/sistemas-operacionais.md`.
