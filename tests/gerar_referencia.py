#!/usr/bin/env python3
"""Gera docs/referencia-template.md a partir do YAML do template.

Uso: python3 tests/gerar_referencia.py
Mantem a documentacao sempre igual ao que o Zabbix importa.
"""
import yaml

SRC = "zabbix/template_linux_vulnerabilidades.yaml"
DST = "docs/referencia-template.md"
zx = yaml.safe_load(open(SRC, encoding="utf-8"))["zabbix_export"]
t = zx["templates"][0]

PRIO = {"INFO": "Informação", "WARNING": "Atenção", "AVERAGE": "Média", "HIGH": "Alta", "DISASTER": "Desastre"}


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def tag(tags, name):
    return next((x["value"] for x in tags or [] if x["tag"] == name), "")


out = []
out.append("# Referência do template\n")
out.append("Este arquivo é gerado por `tests/gerar_referencia.py` a partir de `zabbix/template_linux_vulnerabilidades.yaml`. Não edite à mão.\n")
out.append("## Identificação\n")
out.append(f"| Campo | Valor |\n|---|---|\n| Nome | {esc(t['name'])} |\n| Fornecedor | {esc(t['vendor']['name'])} |\n| Versão | {esc(t['vendor']['version'])} |\n| Grupo | {esc(t['groups'][0]['name'])} |\n| Tags do template | " + ", ".join(f"`{x['tag']}: {x['value']}`" for x in t["tags"]) + " |\n")

out.append("## Item mestre\n")
m = t["items"][0]
out.append(f"O item `{m['key']}` do tipo agente ativo lê o arquivo JSON a cada {m['delay']} e não guarda histórico. Todos os demais itens são dependentes dele e extraem campos por JSONPath.\n")

out.append("## Itens\n")
out.append("| Nome | Chave | Tipo | Valor | Histórico | Componente | JSONPath |\n|---|---|---|---|---|---|---|")
for i in t["items"]:
    jp = ""
    for p in i.get("preprocessing", []):
        if p["type"] == "JSONPATH":
            jp = p["parameters"][0]
    if not jp and i["type"] == "ZABBIX_ACTIVE":
        jp = "arquivo JSON completo"
    vt = i["value_type"] + (f" ({i['valuemap']['name']})" if "valuemap" in i else "")
    out.append(f"| {esc(i['name'])} | `{esc(i['key'])}` | {i['type']} | {vt} | {i.get('history','')} | {tag(i.get('tags'),'component')} | `{esc(jp)}` |")
out.append("")

out.append("## Triggers\n")
out.append("| Nome | Prioridade | Expressão | Escopo | Componente |\n|---|---|---|---|---|")
for i in t["items"]:
    for tr in i.get("triggers", []):
        expr = tr["expression"].replace("/" + t["template"] + "/", "/")
        out.append(f"| {esc(tr['name'])} | {PRIO.get(tr['priority'], tr['priority'])} | `{esc(expr)}` | {tag(tr.get('tags'),'scope')} | {tag(tr.get('tags'),'component')} |")
out.append("")

out.append("## Macros\n")
out.append("| Macro | Padrão | Uso |\n|---|---|---|")
for mc in t["macros"]:
    out.append(f"| `{mc['macro']}` | `{mc['value']}` | {esc(mc['description'])} |")
out.append("")

out.append("## Gráficos\n")
out.append("| Nome | Itens |\n|---|---|")
for g in zx.get("graphs", []):
    out.append(f"| {esc(g['name'])} | " + ", ".join(f"`{gi['item']['key']}`" for gi in g["graph_items"]) + " |")
out.append("")

out.append("## Dashboard do host\n")
for d in t["dashboards"]:
    out.append(f"O dashboard \"{esc(d['name'])}\" aparece em Monitoring > Hosts > Dashboards.\n")
    for p in d["pages"]:
        out.append(f"Página `{p['name']}`\n")
        out.append("| Widget | Tipo | Posição (x, y) | Tamanho (largura x altura) |\n|---|---|---|---|")
        for w in p["widgets"]:
            out.append(f"| {esc(w['name'])} | `{w['type']}` | {w['x']}, {w['y']} | {w['width']} x {w['height']} |")
        out.append("")

out.append("## Value maps\n")
for v in t["valuemaps"]:
    out.append(f"### {esc(v['name'])}\n")
    out.append("| Valor | Exibição |\n|---|---|")
    for mp in v["mappings"]:
        out.append(f"| {mp['value']} | {esc(mp['newvalue'])} |")
    out.append("")

open(DST, "w", encoding="utf-8").write("\n".join(out))
print("gerado", DST)
