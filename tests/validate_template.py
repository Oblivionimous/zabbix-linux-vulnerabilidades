#!/usr/bin/env python3
"""Auditoria estrutural do template Zabbix.

Verifica o que o importador do Zabbix costuma recusar e o que o parser YAML aceita
sem reclamar. Uso: python3 tests/validate_template.py [caminho_do_yaml]
Sai com codigo 1 se encontrar qualquer problema.
"""
import re
import sys

import yaml

PATH = sys.argv[1] if len(sys.argv) > 1 else "zabbix/template_linux_vulnerabilidades.yaml"
UUID4 = re.compile(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}")
TEMPLATE_KEY_ORDER = ["uuid", "template", "name", "description", "vendor", "groups",
                      "items", "tags", "macros", "dashboards", "valuemaps"]


def main():
    with open(PATH, "rb") as f:
        raw = f.read()
    errs = []
    if b"\r" in raw:
        errs.append("arquivo contem CR (CRLF), use somente LF")

    zx = yaml.safe_load(raw.decode("utf-8"))["zabbix_export"]
    t = zx["templates"][0]
    name = t["template"]
    keys = {i["key"] for i in t["items"]}
    names = {i["name"] for i in t["items"]}
    vmaps = {v["name"] for v in t.get("valuemaps", [])}
    macros = {m["macro"] for m in t.get("macros", [])}

    # Graficos e triggers sao chaves de nivel raiz ou aninhadas conforme o esquema oficial
    if "graphs" in t:
        errs.append("'graphs' deve ficar no nivel raiz de zabbix_export, nao dentro do template")
    order = [k for k in t.keys()]
    idx = [TEMPLATE_KEY_ORDER.index(k) for k in order if k in TEMPLATE_KEY_ORDER]
    if idx != sorted(idx):
        errs.append(f"ordem das chaves do template fora do esquema: {order}")
    unknown = [k for k in order if k not in TEMPLATE_KEY_ORDER]
    if unknown:
        errs.append(f"chaves inesperadas no template: {unknown}")

    # Todo valor escalar deve ser texto
    def walk(o, p):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{p}/{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{p}[{i}]")
        elif not isinstance(o, str):
            errs.append(f"valor nao textual em {p}: {o!r} (coloque entre aspas)")
    walk(zx, "")

    # Itens, triggers, value maps e macros
    for i in t["items"]:
        if "master_item" in i and i["master_item"]["key"] not in keys:
            errs.append(f"master_item inexistente em {i['key']}")
        if "valuemap" in i and i["valuemap"]["name"] not in vmaps:
            errs.append(f"value map inexistente em {i['key']}")
        for tr in i.get("triggers", []):
            for host, key in re.findall(r"/([^/]+)/([^,)]+)", tr["expression"]):
                if host != name or key not in keys:
                    errs.append(f"trigger '{tr['name']}' referencia {host}/{key}")
            for m in re.findall(r"\{\$[A-Z0-9_.]+\}", tr["expression"] + tr["name"]):
                if m not in macros:
                    errs.append(f"macro {m} usada e nao declarada")
        if not i.get("description"):
            errs.append(f"item sem descricao {i['key']}")
        if not any(tg["tag"] == "template" for tg in i.get("tags", [])):
            errs.append(f"item sem a tag 'template' {i['key']}")

    # Graficos de nivel raiz
    for g in zx.get("graphs", []):
        for gi in g["graph_items"]:
            if gi["item"]["host"] != name or gi["item"]["key"] not in keys:
                errs.append(f"grafico '{g['name']}' referencia item inexistente {gi['item']}")
            if not re.fullmatch(r"[0-9A-F]{6}", gi["color"]):
                errs.append(f"cor invalida {gi['color']}")

    # Widgets do dashboard
    ref_seen = set()
    for d in t.get("dashboards", []):
        for p in d["pages"]:
            for w in p["widgets"]:
                for f in w["fields"]:
                    if re.fullmatch(r"ds\.\d+\.items\.\d+", f["name"]) and f["value"] not in names:
                        errs.append(f"widget referencia item inexistente '{f['value']}'")
                    if f["name"] == "reference":
                        if f["value"] in ref_seen:
                            errs.append(f"reference duplicado {f['value']}")
                        ref_seen.add(f["value"])

    # UUIDs
    uuids = []

    def collect(o):
        if isinstance(o, dict):
            if "uuid" in o:
                uuids.append(o["uuid"])
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
    collect(zx)
    dup = {u for u in uuids if uuids.count(u) > 1}
    if dup:
        errs.append(f"UUID duplicado {sorted(dup)}")
    bad = [u for u in uuids if not UUID4.fullmatch(u)]
    if bad:
        errs.append(f"UUID fora do formato v4 {bad}")

    trig = sum(len(i.get("triggers", [])) for i in t["items"])
    print(f"itens={len(t['items'])} triggers={trig} graficos={len(zx.get('graphs', []))} "
          f"dashboards={len(t.get('dashboards', []))} valuemaps={len(vmaps)} uuids={len(uuids)}")
    if errs:
        print("PROBLEMAS")
        for e in errs:
            print(" -", e)
        return 1
    print("template OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
