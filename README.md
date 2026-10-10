# Monitoramento de vulnerabilidades Linux no Zabbix

Este projeto mede a quantidade de vulnerabilidades (CVEs) de servidores Linux e entrega os números ao Zabbix 7.0. O foco é estatística e ranking por host, com dados prontos para painéis no Grafana.

A coleta combina duas fontes. O gerenciador de pacotes nativo informa os avisos de segurança pendentes da distribuição. O Trivy varre o sistema de arquivos e identifica achados de CVEs associados a pacotes do sistema e bibliotecas de aplicações. Os resultados dependem da base consultada e do escopo da varredura.

## O que o projeto entrega

- Script `src/vuln-collect.py` que gera um relatório JSON por host.
- Units systemd que executam o script uma vez por dia com limites de CPU, memória e IO.
- [Template Zabbix 7.0](zabbix/template_linux_vulnerabilidades.yaml) com 25 itens, 8 triggers, 4 gráficos e 1 dashboard por host.
- [Dashboard Grafana V2](grafana/dashboard_linux_vulnerabilidades.v2.json) com indicadores da frota, filtros, rankings e mapa de calor em Business Text.
- Instalador, validador e desinstalador em `scripts/`.
- Testes automatizados que conferem o template e a lógica de agregação.
- Documentação da instalação em Rocky Linux, Debian, Ubuntu e Proxmox VE.

## Como funciona

![Fluxo de coleta do Linux ao Zabbix e Grafana](docs/assets/fluxo-coleta.svg)

A coleta roda como root e o agente Zabbix apenas lê o arquivo pronto. Isso evita `sudo` para o usuário `zabbix` e evita estourar o timeout do agente, porque a varredura leva de segundos a minutos. Os detalhes estão em [docs/arquitetura.md](docs/arquitetura.md).

## Indicadores principais

| Indicador | O que responde |
|---|---|
| CVEs corrigíveis por severidade | Quantas falhas têm patch publicado e ainda não foram aplicadas. É o número que exige ação. |
| CVEs corrigíveis em pacotes do SO | O que se resolve com `dnf update` ou `apt upgrade`. |
| CVEs corrigíveis em aplicações | O que depende de uma nova versão do software, como bibliotecas Go dentro de um binário. |
| CVEs únicas | Volume total de falhas distintas, com ou sem correção. |
| Idade da CVE Critical ou High corrigível mais antiga | Dias desde a publicação da CVE. Não mede a data de disponibilidade do patch. |
| Reboot pendente | Se atualizações já instaladas aguardam reinício. |

Os números de CVEs únicas e de CVEs corrigíveis medem coisas diferentes. Uma CVE sem patch publicado entra na primeira e não entra na segunda. A seção "Como interpretar os números" de [docs/arquitetura.md](docs/arquitetura.md) explica com um caso real.

## Requisitos

| Item | Requisito |
|---|---|
| Sistema | RHEL 8 ou superior e derivados (Rocky, Alma), Debian 12 ou superior, Ubuntu 22.04 ou superior |
| Python | 3.6 ou superior, sem bibliotecas externas |
| Arquitetura | x86_64 (o instalador também aceita aarch64) |
| Ferramentas | `systemd`, `jq`, `curl`, `sha256sum`. Em RPM também `yum-utils` para `needs-restarting` |
| Rede | Saída HTTPS para `github.com` (download do trivy) e para os registros de onde o trivy baixa a base de vulnerabilidades |
| Zabbix | Template no formato 7.0 e agente ativo (zabbix-agent ou zabbix-agent2). Validar importação em outras versões |
| Grafana, opcional | Instância compatível com V2 Resource, Business Text e fonte Zabbix. Veja [docs/grafana.md](docs/grafana.md) |

O template foi validado em Zabbix 7.0 com agente clássico 7.0.29 e com agent2.

## Instalação rápida

Em cada host Linux, como root, a partir de uma cópia do repositório.

```bash
git clone https://github.com/oblivionimous/zabbix-linux-vulnerabilidades.git
cd zabbix-linux-vulnerabilidades
RUN_NOW=1 ./scripts/install.sh
./scripts/validate.sh
```

No frontend do Zabbix, importe `zabbix/template_linux_vulnerabilidades.yaml` em Data collection > Templates > Import e vincule o template ao host. O passo a passo completo está em [docs/zabbix.md](docs/zabbix.md).

Para o Grafana, importe `grafana/dashboard_linux_vulnerabilidades.v2.json` após substituir as duas ocorrências de `ZABBIX_DATASOURCE_UID` pelo UID da sua fonte. O export de origem registra Grafana 13.2.3 e Business Text 6.3.0. A versão do plugin Zabbix não está registrada. Confira a importação e as consultas no ambiente de destino conforme [docs/grafana.md](docs/grafana.md).

## Prévias

### Grafana

![Prévia com dados simulados](docs/assets/grafana-exemplo.png)

Prévia local com dados simulados. Ela não comprova importação ou consultas em uma instância Grafana.

### Zabbix

<img width="2557" height="955" alt="image" src="https://github.com/user-attachments/assets/16b355f7-f51f-428c-96fb-df7ae9a3237b" />

Interface aproximada, baseada nos widgets do YAML e no relatório de exemplo. O histórico dos gráficos é fictício.

A [galeria da integração](docs/galeria.md) também apresenta Latest data, coleta e relatório JSON, além do fluxo entre Linux, Zabbix e Grafana.

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/arquitetura.md](docs/arquitetura.md) | Fluxo de dados, decisões de projeto, formato do `report.json`, interpretação dos números |
| [docs/instalacao.md](docs/instalacao.md) | Instalação automática e manual, ajustes por host, limites de recurso |
| [docs/sistemas-operacionais.md](docs/sistemas-operacionais.md) | Particularidades de Rocky/RHEL, Debian, Ubuntu e Proxmox VE |
| [docs/zabbix.md](docs/zabbix.md) | Agente, importação do template, vínculo, macros e validação |
| [docs/referencia-template.md](docs/referencia-template.md) | Itens, triggers, gráficos, macros e widgets gerados a partir do YAML |
| [docs/grafana.md](docs/grafana.md) | Importação do dashboard, plugins, consultas, filtros, índice de saúde e limites |
| [docs/galeria.md](docs/galeria.md) | Prévias do Grafana e Zabbix, relatório de exemplo e diagrama da coleta |
| [docs/publicacao.md](docs/publicacao.md) | Revisão dos exports, verificações e preparação para publicação no GitHub |
| [docs/operacao.md](docs/operacao.md) | Rotina, atualização, runbook por trigger |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Sintomas, causas e correções |
| [docs/piloto.md](docs/piloto.md) | Resultados dos três hosts piloto |
| [docs/licoes-aprendidas.md](docs/licoes-aprendidas.md) | Problemas encontrados na construção e como foram resolvidos |
| [docs/roadmap.md](docs/roadmap.md) | Melhorias planejadas |

## Estrutura do repositório

```
zabbix-linux-vulnerabilidades/
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── src/
│   └── vuln-collect.py               script de coleta, idêntico em todos os hosts
├── config/
│   └── extra-skip-dirs.example       exclusões do trivy por host
├── systemd/
│   ├── vuln-collect.service
│   └── vuln-collect.timer
├── scripts/
│   ├── install.sh
│   ├── validate.sh
│   └── uninstall.sh
├── zabbix/
│   └── template_linux_vulnerabilidades.yaml
├── grafana/
│   ├── dashboard_linux_vulnerabilidades.v2.json
│   ├── business-text-after-render.js
│   ├── business-text-styles.css
│   └── business-text-content.html
├── examples/
│   └── report.example.json
├── docs/
├── tests/
│   ├── validate_template.py
│   ├── test_collect.py
│   ├── test_agregacao.py
│   ├── gerar_referencia.py
│   └── fixtures/trivy_sample.json
└── .github/workflows/validate.yml
```

## Segurança da cadeia de suprimentos

Em março de 2026 o trivy sofreu um ataque à cadeia de suprimentos. A versão v0.69.4 foi publicada com código malicioso e as imagens Docker v0.69.5 e v0.69.6 também foram comprometidas, segundo o [aviso oficial GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) (CVE-2026-33634).

Por causa disso o instalador fixa a versão do trivy, valida o `sha256` do pacote contra o arquivo de checksums da release e recusa as versões comprometidas. Não instale o trivy com um script que baixa "a versão mais recente" sem conferência.

## Testes

```bash
pip install pyyaml
python3 tests/validate_template.py
python3 -m unittest discover -s tests -v
```

O workflow em `.github/workflows/validate.yml` roda os mesmos testes, o `shellcheck` e confere se `docs/referencia-template.md` está em dia.

## Autor e licença

Autor Mauro Paiva. Licença MIT, veja [LICENSE](LICENSE).
