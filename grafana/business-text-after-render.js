// Business Text > JavaScript > After Content Ready
// Painel de vulnerabilidades. Monta todo o conteúdo em HTML e SVG a partir de duas
// consultas da fonte Zabbix.
//   A, modo Metrics, itens numéricos /^Vuln: .*/
//   B, modo Text, rankings e status da coleta
const raiz = context.element;
if (!raiz) return;

// ---------------- Constantes ----------------
const TODOS = "__todos__";
const TOP = 10;
const COR = { CRITICAL: "#ff5468", HIGH: "#ff9a3d", MEDIUM: "#f5cc4a", LOW: "#37d08a", UNKNOWN: "#8793ab", AZUL: "#5b9dff", ROXO: "#b79cff" };
// Texto sobre o fundo de cada selo, com contraste mínimo de 4,5:1
const TXT_SELO = { CRITICAL: "#ffffff", HIGH: "#1a1206", MEDIUM: "#1a1606", LOW: "#04170b", UNKNOWN: "#0b0e14" };
const FUNDO_SELO = { CRITICAL: "#d12a42", HIGH: "#ff9a3d", MEDIUM: "#f5cc4a", LOW: "#37d08a", UNKNOWN: "#a3adc0" };
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const PESO = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const ROT = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", UNKNOWN: "Unknown" };
const ITEM = {
  fixC: "Vuln: CVEs corrigíveis CRITICAL", fixH: "Vuln: CVEs corrigíveis HIGH",
  fixM: "Vuln: CVEs corrigíveis MEDIUM", fixL: "Vuln: CVEs corrigíveis LOW",
  osC: "Vuln: CVEs corrigíveis CRITICAL em pacotes do SO", osH: "Vuln: CVEs corrigíveis HIGH em pacotes do SO",
  appC: "Vuln: CVEs corrigíveis CRITICAL em aplicações", appH: "Vuln: CVEs corrigíveis HIGH em aplicações",
  uniC: "Vuln: CVEs únicas CRITICAL", uniH: "Vuln: CVEs únicas HIGH", uniT: "Vuln: total de CVEs únicas",
  idade: "Vuln: idade da CVE CRITICAL/HIGH corrigível mais antiga (dias)",
  kernel: "Vuln: achados em kernels antigos instalados", reboot: "Vuln: reboot pendente",
  patch: "Vuln: dias desde a última instalação de pacote", dur: "Vuln: duração da coleta",
  ts: "Vuln: horário da última coleta", status: "Vuln: status da coleta",
};
const LIMITE_COLETA_S = 36 * 3600;
const LIMITE_PATCH_DIAS = 60;
const NIVEL = { critico: ["Crítico", COR.CRITICAL], atencao: ["Atenção", COR.HIGH], normal: ["Normal", COR.LOW] };

// Estado preservado entre atualizações do painel
const est = (window.__vulnvz = window.__vulnvz || { host: TODOS, busca: "", corrig: false });
est.hide = est.hide || {};

// ---------------- Utilitários ----------------
const vals = (v) => (v && typeof v.toArray === "function" ? v.toArray() : Array.isArray(v) ? v : []);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const norm = (s) => String(s || "").trim().toLowerCase();
const fmt = (n) => (n == null || !isFinite(n) ? "N/D" : Math.round(n).toLocaleString("pt-BR"));
const soma = (a) => a.reduce((x, y) => x + (Number(y) || 0), 0);
const dataHora = (ms) => new Date(ms).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
const corSaude = (s) => (s >= 90 ? COR.LOW : s >= 70 ? COR.MEDIUM : COR.CRITICAL);
const ITEM_NORM = {};
Object.keys(ITEM).forEach((k) => (ITEM_NORM[norm(ITEM[k])] = k));

// ---------------- Leitura das séries ----------------
function separarNome(frame, field) {
  const cands = [field && field.config && field.config.displayNameFromDS, field && field.config && field.config.displayName, frame && frame.name, field && field.name];
  for (const c of cands) {
    const m = c ? String(c).match(/^(.+?):\s*(Vuln:.+)$/) : null;
    if (m) return { host: m[1].trim(), item: m[2].trim() };
  }
  const lb = (field && field.labels) || {};
  if (lb.host && lb.item) return { host: lb.host, item: lb.item };
  return null;
}

function lerDados(series) {
  const hosts = {};
  const pegar = (h) => (hosts[h] = hosts[h] || { host: h, num: {}, txt: {}, rankC: null, rankP: null, tRank: {} });
  (series || []).forEach((frame) => {
    const campos = frame.fields || [];
    const cTempo = campos.find((f) => f.type === "time");
    const cHost = campos.find((f) => /^host(name)?$/i.test(f.name || ""));
    const cItem = campos.find((f) => /^(item|metric|name)$/i.test(f.name || ""));
    const tempos = cTempo ? vals(cTempo.values) : [];
    const hs = cHost ? vals(cHost.values) : [];
    const its = cItem ? vals(cItem.values) : [];
    campos.forEach((f) => {
      if (f === cTempo || f === cHost || f === cItem) return;
      const base = separarNome(frame, f);
      vals(f.values).forEach((v, k) => {
        if (v == null || v === "") return;
        const host = cHost ? String(hs[k]) : base && base.host;
        const item = cItem ? String(its[k]) : base && base.item;
        if (!host) return;
        const t = Number(tempos[k] != null ? tempos[k] : k);
        const h = pegar(host);
        if (typeof v === "string" && v.trim().charAt(0) === "[") {
          let lista;
          try { lista = JSON.parse(v); } catch (e) { return; }
          if (!Array.isArray(lista)) return;
          const tipo = lista.length && lista[0].package !== undefined ? "rankP" : lista.length && lista[0].cve !== undefined ? "rankC" : /pacote/i.test(item || "") ? "rankP" : "rankC";
          if (h.tRank[tipo] == null || t >= h.tRank[tipo]) { h[tipo] = lista; h.tRank[tipo] = t; }
          return;
        }
        const chave = ITEM_NORM[norm(item)];
        if (!chave) return;
        const num = typeof v === "number" ? v : Number(v);
        if (typeof v !== "string" && isFinite(num)) {
          (h.num[chave] = h.num[chave] || []).push([t, num]);
        } else if (typeof v === "string") {
          const s = h.txt[chave];
          if (!s || t >= s.t) h.txt[chave] = { t, v };
        }
      });
    });
  });
  Object.values(hosts).forEach((h) => Object.values(h.num).forEach((s) => s.sort((a, b) => a[0] - b[0])));
  return hosts;
}

// ---------------- Modelo por host ----------------
function resumirHost(h, agora) {
  const u = (k) => { const s = h.num[k]; return s && s.length ? s[s.length - 1][1] : null; };
  const r = { host: h.host, dados: h };
  Object.keys(ITEM).forEach((k) => { if (k !== "status") r[k] = u(k); });
  r.status = h.txt.status ? String(h.txt.status.v) : null;
  r.idadeColeta = r.ts ? agora / 1000 - r.ts : null;
  r.atrasada = r.idadeColeta != null && r.idadeColeta > LIMITE_COLETA_S;
  r.erro = r.status != null && r.status !== "ok";
  r.fixTotal = soma([r.fixC, r.fixH, r.fixM, r.fixL]);
  r.score = Math.max(0, Math.round(100
    - Math.min(40, (r.fixC || 0) * 20) - Math.min(35, (r.fixH || 0) * 1.5) - Math.min(10, (r.fixM || 0) * 0.3)
    - (r.atrasada ? 10 : 0) - (r.reboot === 1 ? 5 : 0) - (r.erro ? 20 : 0)));
  r.nivel = (r.fixC || 0) > 0 || r.erro ? "critico"
    : (r.fixH || 0) > 0 || r.atrasada || r.reboot === 1 || (r.patch || 0) > LIMITE_PATCH_DIAS ? "atencao" : "normal";
  return r;
}

// Soma de uma chave no tempo, mantendo o último valor de cada host (degrau)
function serieSomada(lista, chave, t0, t1) {
  const series = lista.map((r) => r.dados.num[chave] || []).filter((s) => s.length);
  if (!series.length) return [];
  const ts = Array.from(new Set([].concat.apply([], series.map((s) => s.map((p) => p[0]))).concat([t1]))).filter((t) => t >= t0 && t <= t1).sort((a, b) => a - b);
  const valorEm = (s, t) => { let v = null; for (const p of s) { if (p[0] <= t) v = p[1]; else break; } return v; };
  return [t0].concat(ts).map((t) => [t, soma(series.map((s) => valorEm(s, t) || 0))]);
}

// ---------------- Componentes visuais ----------------
const pct = (v, t) => (!t || !v ? "0%" : v / t < 0.01 ? "<1%" : Math.round((v / t) * 100) + "%");

function spark(pts, cor) {
  if (!pts || pts.length < 2) return "";
  const t0 = pts[0][0], t1 = pts[pts.length - 1][0];
  const mx = Math.max(1, Math.max.apply(null, pts.map((p) => p[1])));
  const x = (t) => ((t - t0) / Math.max(1, t1 - t0)) * 100;
  const y = (v) => 28 - (v / mx) * 26;
  let d = "M" + x(pts[0][0]).toFixed(1) + " " + y(pts[0][1]).toFixed(1);
  for (let k = 1; k < pts.length; k++) d += " H" + x(pts[k][0]).toFixed(1) + " V" + y(pts[k][1]).toFixed(1);
  return '<svg class="vz-spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true"><path d="' + d + '" fill="none" stroke="' + cor + '" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>';
}

// Variação no período. Para vulnerabilidade, subir é ruim.
function delta(pts) {
  if (!pts || pts.length < 2) return "";
  const d = pts[pts.length - 1][1] - pts[0][1];
  if (!d) return '<span class="vz-delta vz-eq" title="Sem variação no período">= 0</span>';
  return '<span class="vz-delta ' + (d > 0 ? "vz-up" : "vz-down") + '" title="Variação no período selecionado">' + (d > 0 ? "▲ +" : "▼ ") + fmt(d) + "</span>";
}

// ---------------- Rankings ----------------
function agregarCves(lista) {
  const m = {};
  lista.forEach((r) => (r.dados.rankC || []).forEach((c) => {
    const sev = String(c.severity || "UNKNOWN").toUpperCase();
    const e = (m[c.cve] = m[c.cve] || { cve: c.cve, sev, score: 0, fix: false, cls: new Set(), pk: new Set(), hs: new Set() });
    if ((PESO[sev] || 0) > (PESO[e.sev] || 0)) e.sev = sev;
    e.score = Math.max(e.score, Number(c.score) || 0);
    e.fix = e.fix || !!c.fixable;
    String(c.class || "").split(",").filter(Boolean).forEach((x) => e.cls.add(x));
    String(c.packages || "").split(",").filter(Boolean).forEach((x) => e.pk.add(x));
    e.hs.add(r.host);
  }));
  return Object.values(m).sort((a, b) => PESO[b.sev] - PESO[a.sev] || b.fix - a.fix || b.hs.size - a.hs.size || b.score - a.score);
}

function agregarPacotes(lista) {
  const m = {};
  lista.forEach((r) => (r.dados.rankP || []).forEach((p) => {
    const e = (m[p.package] = m[p.package] || { nome: p.package, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, total: 0, hs: new Set() });
    SEVS.forEach((s) => (e[s] += Number(p[s.toLowerCase()]) || 0));
    e.total += Number(p.total) || 0;
    e.hs.add(r.host);
  }));
  return Object.values(m).sort((a, b) => b.CRITICAL - a.CRITICAL || b.HIGH - a.HIGH || b.total - a.total);
}

const selo = (s) => '<span class="vz-badge" style="background:' + FUNDO_SELO[s] + ";color:" + TXT_SELO[s] + '">' + ROT[s] + "</span>";

function tabelaCves(cves, todosHosts) {
  if (!cves.length) return '<div class="vz-vazio">Nenhuma CVE no filtro atual.</div>';
  const cls = (c) => Array.from(c.cls).map((x) => (x === "os-pkgs" ? "SO" : x === "lang-pkgs" ? "Aplicação" : x)).join(" + ");
  const pk = (c) => { const a = Array.from(c.pk); return a.slice(0, 2).map((x) => '<span class="vz-chip">' + esc(x) + "</span>").join("") + (a.length > 2 ? '<span class="vz-chip" title="' + esc(a.slice(2).join(", ")) + '">+' + (a.length - 2) + "</span>" : ""); };
  return '<div class="vz-scroll"><table class="vz-tab"><caption class="vz-sr">CVEs de maior risco, ordenadas por severidade, correção e alcance</caption><thead><tr><th scope="col">Sev.</th><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">Situação</th><th scope="col">Pacotes</th>' + (todosHosts ? '<th scope="col" class="vz-r">Hosts</th>' : "") + "</tr></thead><tbody>" +
    cves.slice(0, TOP).map((c) => "<tr><td>" + selo(c.sev) + '</td><td><a class="vz-link" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c.cve) + '" title="Abrir ' + esc(c.cve) + ' no NVD (nova aba)">' + esc(c.cve) + "</a></td>" +
      '<td><div class="vz-cvss" title="CVSS ' + (c.score ? c.score.toFixed(1) : "não informado") + '"><div style="width:' + Math.min(100, c.score * 10) + "%;background:" + COR[c.sev] + '"></div><span>' + (c.score ? c.score.toFixed(1) : "N/D") + "</span></div></td>" +
      "<td>" + (c.fix ? '<span class="vz-pill vz-pill-ok">Corrigível</span>' : '<span class="vz-pill">Sem correção</span>') + "<small>" + esc(cls(c)) + "</small></td><td class=\"vz-quebra\">" + pk(c) + "</td>" +
      (todosHosts ? '<td class="vz-r vz-num" title="' + esc(Array.from(c.hs).join(", ")) + '">' + c.hs.size + "</td>" : "") + "</tr>").join("") + "</tbody></table></div>";
}

function listarAlertas(lista) {
  const out = [];
  lista.forEach((r) => {
    if (r.erro) out.push(["critico", r.host, "Coleta com erro (status " + r.status + ")"]);
    if (r.fixC > 0) out.push(["critico", r.host, fmt(r.fixC) + " CVE(s) Critical com correção disponível"]);
    if (r.fixH > 0) out.push(["atencao", r.host, fmt(r.fixH) + " CVE(s) High com correção disponível" + ((r.appH || 0) === r.fixH ? ", todas em aplicações" : "")]);
    if (r.atrasada) out.push(["atencao", r.host, "Relatório com mais de 36 horas"]);
    if (r.reboot === 1) out.push(["atencao", r.host, "Reboot pendente"]);
    if ((r.patch || 0) > LIMITE_PATCH_DIAS) out.push(["atencao", r.host, "Sem instalar pacotes há " + fmt(r.patch) + " dias"]);
    if ((r.idade || 0) > 90) out.push(["atencao", r.host, "Correção pendente mais antiga com " + fmt(r.idade) + " dias"]);
    if ((r.kernel || 0) > 0) out.push(["info", r.host, fmt(r.kernel) + " achados em kernels antigos ainda instalados"]);
  });
  const ordem = { critico: 0, atencao: 1, info: 2 };
  return out.sort((a, b) => ordem[a[0]] - ordem[b[0]]);
}


// ---------------- Ícones (traço 2, grade 24) ----------------
const IC = {
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
  bug: '<path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/>',
  wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.106-3.105c.32-.322.863-.22.983.218a6 6 0 0 1-8.259 7.057l-7.91 7.91a1 1 0 0 1-2.999-3l7.91-7.91a6 6 0 0 1 7.057-8.259c.438.12.54.662.219.984z"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  power: '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
  server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>',
  bell: '<path d="M10.268 21a2 2 0 0 0 3.464 0"/><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
};
const icone = (k) => '<svg class="vz-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + IC[k] + "</svg>";

// Medidor em arco de 240 graus para o índice de saúde
function medidor(score, cor) {
  const cx = 100, cy = 100, R = 78, a0 = 150, sw = 240;
  const pol = (a, r) => { const t = (a * Math.PI) / 180; return [cx + (r || R) * Math.cos(t), cy + (r || R) * Math.sin(t)]; };
  const arco = (da) => { const p0 = pol(a0), p1 = pol(a0 + da); return "M" + p0[0].toFixed(2) + " " + p0[1].toFixed(2) + " A" + R + " " + R + " 0 " + (da > 180 ? 1 : 0) + " 1 " + p1[0].toFixed(2) + " " + p1[1].toFixed(2); };
  const fim = Math.max(2, sw * Math.min(1, score / 100));
  const marca = [70, 90].map((v) => { const a = a0 + sw * (v / 100), i = pol(a, R - 14), o = pol(a, R + 14); return '<line x1="' + i[0].toFixed(1) + '" y1="' + i[1].toFixed(1) + '" x2="' + o[0].toFixed(1) + '" y2="' + o[1].toFixed(1) + '" class="vz-g-marca"/>'; }).join("");
  const k = pol(a0 + fim);
  return '<svg class="vz-medidor" viewBox="0 0 200 158" role="img" aria-label="Índice de saúde ' + score + ' de 100">' +
    '<path d="' + arco(sw) + '" class="vz-g-trilho"/>' + marca +
    '<path d="' + arco(fim) + '" class="vz-g-valor" pathLength="1" style="stroke:' + cor + ";filter:drop-shadow(0 0 6px " + cor + '88)"/>' +
    '<circle cx="' + k[0].toFixed(2) + '" cy="' + k[1].toFixed(2) + '" r="8" class="vz-g-knob" style="fill:' + cor + '"/>' +
    '<text x="100" y="108" class="vz-g-n">' + score + '</text><text x="100" y="128" class="vz-g-s">de 100</text></svg>';
}

// Anel pequeno de proporção
function anel(v, t, cor) {
  const R = 17, C = 2 * Math.PI * R, f = t ? Math.min(1, v / t) : 0;
  return '<svg class="vz-anel" viewBox="0 0 44 44" aria-hidden="true"><circle cx="22" cy="22" r="' + R + '" class="vz-an-trilho"/><circle cx="22" cy="22" r="' + R + '" class="vz-an-valor" style="stroke:' + cor + '" stroke-dasharray="' + (f * C).toFixed(2) + " " + C.toFixed(2) + '" transform="rotate(-90 22 22)"/></svg>';
}

// Barra segmentada com legenda (substitui as roscas)
function composicao(titulo, segs, rotulo) {
  const total = soma(segs.map((s) => s.v));
  const barra = total ? segs.filter((s) => s.v > 0).map((s) => '<i style="flex:' + s.v + ";background:" + s.cor + '" title="' + esc(s.nome) + ": " + fmt(s.v) + " (" + pct(s.v, total) + ')"></i>').join("") : "";
  const leg = segs.map((s) => '<li class="vz-leg"><i style="background:' + s.cor + '"></i><span>' + esc(s.nome) + "</span><b>" + fmt(s.v) + "</b><em>" + pct(s.v, total) + "</em></li>").join("");
  return '<div class="vz-seg"><div class="vz-seg-h"><span>' + esc(titulo) + '</span><b class="vz-num">' + fmt(total) + '</b></div><div class="vz-seg-bar" role="img" aria-label="' + esc(rotulo) + '">' + (barra || '<i style="flex:1;background:transparent"></i>') + '</div><ul class="vz-legs vz-legs-grid">' + leg + "</ul></div>";
}

// Gráfico de degraus com rótulos diretos nas pontas, na largura real do contêiner
function desenharLinhas(alvo, series, t0, t1) {
  const W = Math.max(300, alvo.clientWidth), H = 250, L = 44, B = 28, T = 14, Rt = 46;
  const todos = [].concat.apply([], series.map((s) => s.pts.map((p) => p[1])));
  if (!series.length) { alvo.innerHTML = '<div class="vz-vazio">Todas as séries estão ocultas. Use a legenda para exibir.</div>'; return; }
  if (!todos.length) { alvo.innerHTML = '<div class="vz-vazio">Sem histórico no período.</div>'; return; }
  let max = Math.max(1, Math.max.apply(null, todos));
  const pot = Math.pow(10, Math.floor(Math.log10(max)));
  max = Math.ceil(max / pot) * pot;
  const x = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * (W - L - Rt);
  const y = (v) => T + (1 - v / max) * (H - T - B);
  const nTicks = Math.max(1, Math.min(6, Math.floor((W - L - Rt) / 130)));
  let g = "";
  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i, yy = y(v).toFixed(1);
    g += '<line x1="' + L + '" x2="' + (W - Rt) + '" y1="' + yy + '" y2="' + yy + '" class="vz-grid"/><text x="' + (L - 10) + '" y="' + (+yy + 4) + '" class="vz-eixo" text-anchor="end">' + fmt(v) + "</text>";
  }
  for (let i = 0; i <= nTicks; i++) {
    const t = t0 + ((t1 - t0) / nTicks) * i;
    g += '<text x="' + x(t).toFixed(1) + '" y="' + (H - 8) + '" class="vz-eixo" text-anchor="' + (i === 0 ? "start" : i === nTicks ? "end" : "middle") + '">' + esc(dataHora(t)) + "</text>";
  }
  const defs = series.map((s, i) => '<linearGradient id="vzg' + i + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="' + s.cor + '" stop-opacity=".30"/><stop offset="1" stop-color="' + s.cor + '" stop-opacity="0"/></linearGradient>').join("");
  const traco = series.map((s, i) => {
    if (!s.pts.length) return "";
    let d = "M" + x(s.pts[0][0]).toFixed(1) + " " + y(s.pts[0][1]).toFixed(1);
    for (let k = 1; k < s.pts.length; k++) d += " H" + x(s.pts[k][0]).toFixed(1) + " V" + y(s.pts[k][1]).toFixed(1);
    d += " H" + x(t1).toFixed(1);
    const area = d + " V" + (H - B) + " H" + x(s.pts[0][0]).toFixed(1) + " Z";
    return '<path d="' + area + '" fill="url(#vzg' + i + ')"/><path d="' + d + '" fill="none" stroke="' + s.cor + '" stroke-width="2.25" stroke-linejoin="round" stroke-linecap="round"/>';
  }).join("");
  // Rótulos nas pontas, com afastamento vertical mínimo para não se sobrepor
  const pontas = series.filter((s) => s.pts.length).map((s) => ({ s, v: s.pts[s.pts.length - 1][1], y: y(s.pts[s.pts.length - 1][1]) })).sort((a, b) => a.y - b.y);
  for (let i = 1; i < pontas.length; i++) if (pontas[i].y - pontas[i - 1].y < 14) pontas[i].y = pontas[i - 1].y + 14;
  const rotulos = pontas.map((p) => '<circle cx="' + x(t1).toFixed(1) + '" cy="' + y(p.v).toFixed(1) + '" r="4" fill="' + p.s.cor + '" stroke="var(--card)" stroke-width="2"/><text x="' + (x(t1) + 10).toFixed(1) + '" y="' + (p.y + 4).toFixed(1) + '" class="vz-eixo vz-fim" fill="' + p.s.cor + '">' + fmt(p.v) + "</text>").join("");
  const resumo = series.map((s) => s.nome + " " + fmt(s.pts.length ? s.pts[s.pts.length - 1][1] : 0)).join(", ");
  alvo.innerHTML = '<svg viewBox="0 0 ' + W + " " + H + '" width="' + W + '" height="' + H + '" role="img" aria-label="Evolução das CVEs corrigíveis. Valores atuais ' + esc(resumo) + '"><defs>' + defs + "</defs>" + g + traco + rotulos +
    '<line class="vz-cursor" x1="0" x2="0" y1="' + T + '" y2="' + (H - B) + '" style="display:none"/><rect x="' + L + '" y="' + T + '" width="' + (W - L - Rt) + '" height="' + (H - T - B) + '" fill="transparent"/></svg><div class="vz-tip" style="display:none"></div>';

  const svg = alvo.querySelector("svg"), cur = alvo.querySelector(".vz-cursor"), tip = alvo.querySelector(".vz-tip"), area = svg.querySelector("rect[fill=transparent]");
  const valorEm = (pts, t) => { let v = null; for (const p of pts) { if (p[0] <= t) v = p[1]; else break; } return v; };
  area.addEventListener("mousemove", (e) => {
    const bx = svg.getBoundingClientRect();
    const px = ((e.clientX - bx.left) / bx.width) * W;
    const t = t0 + ((px - L) / (W - L - Rt)) * (t1 - t0);
    cur.setAttribute("x1", px); cur.setAttribute("x2", px); cur.style.display = "";
    tip.innerHTML = "<div><span>" + esc(dataHora(t)) + "</span></div>" + series.map((s) => '<div><i style="background:' + s.cor + '"></i><span>' + esc(s.nome) + "</span><b>" + fmt(valorEm(s.pts, t) || 0) + "</b></div>").join("");
    tip.style.display = "";
    const esq = px + 14 + tip.offsetWidth > W ? px - 14 - tip.offsetWidth : px + 14;
    tip.style.left = Math.max(0, esq) + "px"; tip.style.top = "8px";
  });
  area.addEventListener("mouseleave", () => { cur.style.display = "none"; tip.style.display = "none"; });
}

// Hosts com mais CVEs corrigíveis: barras empilhadas na mesma escala
function barrasHosts(lista) {
  const dados = lista.filter((r) => r.fixTotal > 0).sort((a, b) => b.fixTotal - a.fixTotal).slice(0, TOP);
  if (!dados.length) return '<div class="vz-vazio vz-ok">Nenhuma CVE corrigível pendente.</div>';
  const max = Math.max.apply(null, dados.map((r) => r.fixTotal));
  const linhas = dados.map((r, i) => {
    const segs = [["CRITICAL", r.fixC], ["HIGH", r.fixH], ["MEDIUM", r.fixM], ["LOW", r.fixL]].filter((s) => s[1])
      .map(([s, v]) => '<i style="flex:' + v + ";background:" + COR[s] + '" title="' + ROT[s] + ": " + fmt(v) + '"></i>').join("");
    return '<li class="vz-hb-row"><span class="vz-hb-pos vz-num">' + (i + 1) + '</span><button type="button" data-host="' + esc(r.host) + '" title="' + esc(r.host) + ', filtrar por este host">' + esc(r.host) + '</button><div class="vz-hb-trilho"><div class="vz-hb-bar" role="img" aria-label="' + esc(r.host) + ", Critical " + fmt(r.fixC) + ", High " + fmt(r.fixH) + ", Medium " + fmt(r.fixM) + ", Low " + fmt(r.fixL) + '" style="width:' + ((r.fixTotal / max) * 100).toFixed(2) + '%">' + segs + "</div></div><b>" + fmt(r.fixTotal) + "</b></li>";
  }).join("");
  const leg = '<ul class="vz-legs vz-legs-row">' + ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => '<li class="vz-leg"><i style="background:' + COR[s] + '"></i><span>' + ROT[s] + "</span></li>").join("") + "</ul>";
  return '<ul class="vz-hb">' + linhas + "</ul>" + leg;
}

// Pacotes como blocos proporcionais ao total de CVEs, com a pior severidade na borda
function blocosPacotes(pacs) {
  if (!pacs.length) return '<div class="vz-vazio">Nenhum pacote no filtro atual.</div>';
  const top = pacs.slice(0, 12);
  return '<ol class="vz-treemap">' + top.map((p, i) => {
    const pior = SEVS.find((s) => p[s]) || "UNKNOWN";
    const seg = SEVS.filter((s) => p[s]).map((s) => '<i style="flex:' + p[s] + ";background:" + COR[s] + '" title="' + ROT[s] + ": " + fmt(p[s]) + '"></i>').join("");
    const nums = SEVS.filter((s) => p[s] && s !== "UNKNOWN").slice(0, 3).map((s) => '<span style="color:' + COR[s] + '" title="' + ROT[s] + '">' + ROT[s].charAt(0) + " " + fmt(p[s]) + "</span>").join("");
    return '<li class="vz-pk" style="flex:' + Math.max(1, p.total) + ' 1 150px;--c:' + COR[pior] + '"><div class="vz-pk-top"><span class="vz-pk-pos vz-num">' + (i + 1) + '</span><span class="vz-pk-nome" title="' + esc(p.nome) + '">' + esc(p.nome) + '</span></div><div class="vz-pk-n vz-num">' + fmt(p.total) + '<small>CVEs</small></div><div class="vz-pk-bar">' + seg + '</div><div class="vz-pk-f vz-num">' + nums + "<em>" + p.hs.size + " host" + (p.hs.size > 1 ? "s" : "") + "</em></div></li>";
  }).join("") + "</ol>";
}

function alertasHtml(out, extra) {
  if (!out.length) return '<div class="vz-vazio vz-ok">Nenhum ponto de atenção.</div>';
  const cor = { critico: COR.CRITICAL, atencao: COR.HIGH, info: COR.AZUL };
  const rot = { critico: "Crítico", atencao: "Atenção", info: "Info" };
  return '<ul class="vz-als ' + (extra || "") + '" tabindex="0" aria-label="Lista de pontos de atenção">' + out.map((a) => '<li class="vz-al" style="--c:' + cor[a[0]] + '"><i aria-hidden="true"></i><b>' + esc(a[1]) + "</b><em>" + rot[a[0]] + "</em><span>" + esc(a[2]) + "</span></li>").join("") + "</ul>";
}

// ---------------- Montagem ----------------
function kpi(ic, titulo, valor, cor, sub, extra) {
  return '<article class="vz-kpi" style="--c:' + cor + '"><span class="vz-kpi-i">' + icone(ic) + '</span><div class="vz-kpi-c"><p class="vz-kpi-t">' + titulo + '</p><p class="vz-kpi-v">' + valor + '</p><div class="vz-kpi-s">' + (sub || "") + "</div></div>" + (extra || "") + "</article>";
}

function bloco(titulo, corpo, cls, direita, ic) {
  return '<section class="vz-card ' + (cls || "") + '"><header><h3>' + (ic ? icone(ic) : "") + titulo + "</h3>" + (direita || "") + "</header>" + corpo + "</section>";
}

let ro = null, tBusca = null;

function desenhar() {
  const pd = (context.panel && context.panel.panelData) || context.panelData || {};
  const agora = Date.now();
  const todos = Object.values(lerDados(pd.series || [])).map((h) => resumirHost(h, agora)).sort((a, b) => a.score - b.score || a.host.localeCompare(b.host));

  if (!todos.length) {
    raiz.innerHTML = '<div class="vz-root"><div class="vz-vazio">Sem dados. Confira as consultas A (Metrics, itens /^Vuln: .*/) e B (Text, rankings e status).</div></div>';
    return;
  }
  if (est.host !== TODOS && !todos.some((r) => r.host === est.host)) est.host = TODOS;
  const ambiente = est.host === TODOS;
  const sel = ambiente ? todos : todos.filter((r) => r.host === est.host);

  const tr = pd.timeRange || {};
  const t1 = tr.to ? +tr.to : agora;
  const t0 = tr.from ? +tr.from : t1 - 86400000;

  const S = (k) => soma(sel.map((r) => r[k]));
  const fixC = S("fixC"), fixH = S("fixH"), fixM = S("fixM"), fixL = S("fixL"), fixT = fixC + fixH + fixM + fixL;
  const uniC = S("uniC"), uniH = S("uniH"), uniT = S("uniT");
  const scoreMed = Math.round(soma(sel.map((r) => r.score)) / sel.length);
  const emRisco = todos.filter((r) => r.nivel !== "normal").length;
  const emDia = todos.filter((r) => r.ts && !r.atrasada && !r.erro).length;
  const ultima = Math.max.apply(null, todos.map((r) => r.ts || 0));
  const sC = serieSomada(sel, "fixC", t0, t1), sH = serieSomada(sel, "fixH", t0, t1), sM = serieSomada(sel, "fixM", t0, t1);
  const idades = sel.map((r) => r.idade).filter((v) => v != null);
  const maxIdade = idades.length ? Math.max.apply(null, idades) : null;
  const reboots = sel.filter((r) => r.reboot === 1).length;
  const nCrit = todos.filter((r) => r.nivel === "critico").length, nAten = todos.filter((r) => r.nivel === "atencao").length, nNorm = todos.length - nCrit - nAten;

  const corScore = corSaude(scoreMed);
  const veredito = scoreMed >= 90 ? "Hosts saudáveis" : scoreMed >= 70 ? "Requer atenção" : "Situação crítica";

  // Postura: medidor + resumo
  const postura = '<div class="vz-post">' + medidor(scoreMed, corScore) +
    '<div class="vz-post-t"><p class="vz-veredito" style="color:' + corScore + '">' + veredito + '</p><p class="vz-post-s">' +
    (ambiente ? "Média do índice de saúde dos " + todos.length + " hosts." : "Índice de saúde de " + esc(est.host) + ".") + "</p>" +
    '<ul class="vz-stats"><li><b class="vz-num" style="color:' + (emRisco ? COR.HIGH : COR.LOW) + '">' + emRisco + "<small>/" + todos.length + "</small></b><span>hosts em risco</span></li>" +
    '<li><b class="vz-num" style="color:' + (emDia === todos.length ? COR.LOW : COR.CRITICAL) + '">' + emDia + "<small>/" + todos.length + "</small></b><span>coletas em dia</span></li></ul></div></div>";

  // Exposição: números grandes + gráfico
  const grande = (nome, v, cor, pts) => '<div class="vz-big" style="--c:' + cor + '"><span class="vz-big-n">' + nome + '</span><b class="vz-num">' + fmt(v) + "</b>" + delta(pts) + "</div>";
  const series = [{ nome: "Critical", cor: COR.CRITICAL, pts: sC }, { nome: "High", cor: COR.HIGH, pts: sH }, { nome: "Medium", cor: COR.MEDIUM, pts: sM }];
  const legenda = '<div class="vz-lgs" role="group" aria-label="Séries do gráfico">' + series.map((s) => '<button type="button" class="vz-lg" data-serie="' + s.nome + '" aria-pressed="' + !est.hide[s.nome] + '"><i style="background:' + s.cor + '"></i>' + s.nome + "<b>" + fmt(s.pts.length ? s.pts[s.pts.length - 1][1] : 0) + "</b></button>").join("") + "</div>";
  const exposicao = '<div class="vz-bigs">' + grande("Critical", fixC, COR.CRITICAL, sC) + grande("High", fixH, COR.HIGH, sH) + grande("Medium", fixM, COR.MEDIUM, sM) + "</div>" +
    '<div class="vz-chart" data-chart="evol"></div>' + legenda;

  const kpis = '<div class="vz-kpis">' +
    kpi("bug", "CVEs únicas", fmt(uniT), COR.AZUL, ambiente ? "soma por host" : "no host") +
    kpi("wrench", "Com correção", pct(fixT, uniT), COR.LOW, fmt(fixT) + " de " + fmt(uniT), anel(fixT, uniT, COR.LOW)) +
    kpi("clock", "Pendência mais antiga", maxIdade == null ? "N/D" : fmt(maxIdade) + "<small> dias</small>", maxIdade > 365 ? COR.CRITICAL : maxIdade > 90 ? COR.HIGH : COR.LOW, "Critical ou High corrigível") +
    kpi("power", "Reboots pendentes", fmt(reboots) + "<small>/" + sel.length + "</small>", reboots ? COR.HIGH : COR.LOW, reboots ? "reinício necessário" : "nenhum pendente") +
    "</div>";

  const comp = composicao("Severidade das CVEs únicas", [{ nome: "Critical", v: uniC, cor: COR.CRITICAL }, { nome: "High", v: uniH, cor: COR.HIGH }, { nome: "Medium e Low", v: Math.max(0, uniT - uniC - uniH), cor: COR.MEDIUM }], "CVEs únicas por severidade") +
    composicao("Origem das corrigíveis Critical e High", [{ nome: "Pacotes do SO", v: S("osC") + S("osH"), cor: COR.AZUL }, { nome: "Aplicações", v: S("appC") + S("appH"), cor: COR.ROXO }], "CVEs Critical e High corrigíveis por origem") +
    composicao("Correção disponível", [{ nome: "Corrigíveis", v: fixT, cor: COR.LOW }, { nome: "Sem correção", v: Math.max(0, uniT - fixT), cor: COR.UNKNOWN }], "Proporção de CVEs com correção disponível");

  let cves = agregarCves(sel);
  if (est.corrig) cves = cves.filter((c) => c.fix);
  const b = norm(est.busca);
  if (b) cves = cves.filter((c) => c.cve.toLowerCase().includes(b) || Array.from(c.pk).some((p) => p.toLowerCase().includes(b)));
  let pacs = agregarPacotes(sel);
  if (b) pacs = pacs.filter((p) => p.nome.toLowerCase().includes(b));

  // Hosts: um quadrado por host, colorido pelo nível
  const quadroHosts = '<div class="vz-hosts" role="group" aria-label="Hosts. Selecione um para filtrar o painel">' + todos.map((r) => {
    const [rot] = NIVEL[r.nivel];
    const ch = (r.fixC || 0) + (r.fixH || 0);
    return '<button type="button" class="vz-sq vz-' + r.nivel + '" data-host="' + esc(r.host) + '" aria-pressed="' + (r.host === est.host) + '" title="' + esc(r.host) + ", " + rot + ", saúde " + r.score + ", " + ch + ' Critical e High corrigíveis" aria-label="' + esc(r.host) + ", " + rot + ", saúde " + r.score + ", " + ch + ' CVEs Critical e High corrigíveis"><span class="vz-num" aria-hidden="true">' + (ch > 99 ? "99+" : ch) + "</span></button>";
  }).join("") + "</div>" +
    '<ul class="vz-legs vz-legs-row"><li class="vz-leg"><i style="background:' + COR.CRITICAL + '"></i><span>Crítico</span><b>' + nCrit + '</b></li><li class="vz-leg"><i style="background:' + COR.HIGH + '"></i><span>Atenção</span><b>' + nAten + '</b></li><li class="vz-leg"><i style="background:' + COR.LOW + '"></i><span>Normal</span><b>' + nNorm + "</b></li></ul>" +
    '<p class="vz-nota">O número em cada quadrado soma Critical e High corrigíveis.</p>';

  // Mapa de calor por host
  const mx = (k) => Math.max(1, Math.max.apply(null, todos.map((r) => r[k] || 0)));
  const mC = mx("fixC"), mH = mx("fixH"), mM = mx("fixM"), mL = mx("fixL"), mU = mx("uniT");
  const calor = (cor, v, max) => (v > 0 ? ' style="background:color-mix(in srgb,' + cor + " " + Math.round(12 + (v / max) * 30) + '%,transparent)"' : "");
  const th = (txt, dica, dir) => '<th scope="col"' + (dir ? ' class="vz-r"' : "") + ">" + (dica ? '<abbr title="' + esc(dica) + '">' + txt + "</abbr>" : txt) + "</th>";
  const matriz = '<div class="vz-scroll"><table class="vz-tab vz-matriz"><caption class="vz-sr">Mapa de calor da situação de cada host. Selecione o nome para filtrar o painel</caption><thead><tr>' +
    th("Host") + th("Saúde", "Índice de 0 a 100, regra no rodapé") + th("Critical", "CVEs Critical corrigíveis", 1) + th("High", "CVEs High corrigíveis", 1) + th("Medium", "CVEs Medium corrigíveis", 1) + th("Low", "CVEs Low corrigíveis", 1) +
    th("Únicas", "Total de CVEs únicas no host", 1) + th("Pend. antiga", "Idade da CVE Critical ou High corrigível mais antiga", 1) + th("Últ. pacote", "Dias desde a última instalação de pacote", 1) + th("Reboot") + th("Coleta") + th("Duração", "Tempo de execução da coleta", 1) +
    "</tr></thead><tbody>" +
    todos.map((r) => {
      const col = r.erro ? '<span class="vz-pill vz-pill-err">erro</span>' : r.atrasada ? '<span class="vz-pill vz-pill-warn">atrasada</span>' : '<span class="vz-pill vz-pill-ok">ok</span>';
      const reb = r.reboot === 1 ? '<span class="vz-pill vz-pill-warn">sim</span>' : r.reboot === 0 ? "não" : "N/D";
      const corIdade = (r.idade || 0) > 365 ? COR.CRITICAL : (r.idade || 0) > 90 ? COR.HIGH : "inherit";
      const [rot, cor] = NIVEL[r.nivel];
      return '<tr class="' + (r.host === est.host ? "vz-row-sel" : "") + '"><td><button type="button" class="vz-hostbtn" data-host="' + esc(r.host) + '" aria-pressed="' + (r.host === est.host) + '"><span class="vz-dot" style="background:' + cor + '" aria-hidden="true"></span>' + esc(r.host) + '<small class="vz-sr"> ' + rot + "</small></button></td>" +
        '<td class="vz-num"><span class="vz-mini" aria-hidden="true"><i style="width:' + r.score + "%;background:" + corSaude(r.score) + '"></i></span>' + r.score + "</td>" +
        '<td class="vz-r vz-num"><span class="vz-hc"' + calor(COR.CRITICAL, r.fixC, mC) + ">" + fmt(r.fixC) + '</span></td><td class="vz-r vz-num"><span class="vz-hc"' + calor(COR.HIGH, r.fixH, mH) + ">" + fmt(r.fixH) + '</span></td><td class="vz-r vz-num"><span class="vz-hc"' + calor(COR.MEDIUM, r.fixM, mM) + ">" + fmt(r.fixM) + '</span></td><td class="vz-r vz-num"><span class="vz-hc"' + calor(COR.LOW, r.fixL, mL) + ">" + fmt(r.fixL) + "</span></td>" +
        '<td class="vz-r vz-num"><span class="vz-hc"' + calor(COR.AZUL, r.uniT, mU) + ">" + fmt(r.uniT) + '</span></td><td class="vz-r vz-num" style="color:' + corIdade + '">' + fmt(r.idade) + ' d</td><td class="vz-r vz-num">' + fmt(r.patch) + " d</td><td>" + reb + "</td><td>" + col + (r.ts ? "<small>" + esc(dataHora(r.ts * 1000)) + "</small>" : "") + '</td><td class="vz-r vz-num">' + fmt(r.dur) + " s</td></tr>";
    }).join("") + "</tbody></table></div>";

  const opcoes = '<option value="' + TODOS + '"' + (ambiente ? " selected" : "") + ">Todos os hosts (" + todos.length + ")</option>" +
    todos.map((r) => '<option value="' + esc(r.host) + '"' + (r.host === est.host ? " selected" : "") + ">" + esc(r.host) + "</option>").join("");

  const filtros = [];
  if (!ambiente) filtros.push('<button type="button" class="vz-chip-f" data-limpa="host" aria-label="Remover filtro de host ' + esc(est.host) + '">Host ' + esc(est.host) + "<b aria-hidden=\"true\">×</b></button>");
  if (b) filtros.push('<button type="button" class="vz-chip-f" data-limpa="busca" aria-label="Remover filtro de texto">Texto "' + esc(est.busca) + '"<b aria-hidden="true">×</b></button>');
  if (est.corrig) filtros.push('<button type="button" class="vz-chip-f" data-limpa="corrig" aria-label="Remover filtro só corrigíveis">Só corrigíveis<b aria-hidden="true">×</b></button>');

  const alertas = listarAlertas(sel);
  const nA = (t) => alertas.filter((a) => a[0] === t).length;
  const resumoAl = '<ul class="vz-legs vz-legs-row"><li class="vz-leg"><i style="background:' + COR.CRITICAL + '"></i><span>Crítico</span><b>' + nA("critico") + '</b></li><li class="vz-leg"><i style="background:' + COR.HIGH + '"></i><span>Atenção</span><b>' + nA("atencao") + '</b></li><li class="vz-leg"><i style="background:' + COR.AZUL + '"></i><span>Info</span><b>' + nA("info") + "</b></li></ul>";
  const blocoAlertas = resumoAl + alertasHtml(alertas);

  const anim = est.animado ? "" : " vz-anim";
  est.animado = true;

  raiz.innerHTML = '<div class="vz-root' + anim + '"><div class="vz-shell">' +
    '<aside class="vz-rail">' +
    '<div class="vz-marca"><span class="vz-logo">' + icone("shield") + '</span><div><h2 class="vz-titulo">Vulnerabilidades</h2><p>Hosts Linux · Trivy e gerenciador de pacotes</p></div></div>' +
    '<div class="vz-ultima"><span>Última coleta</span><b class="vz-num">' + (ultima ? esc(dataHora(ultima * 1000)) : "sem registro") + '</b><div class="vz-clock" aria-label="Hora local"><i aria-hidden="true"></i><span class="vz-num" data-vz="clock">--:--:--</span></div></div>' +
    '<div class="vz-ctrl" role="search"><div class="vz-f"><label for="vz-host">Escopo</label><select id="vz-host" class="vz-campo vz-sel" data-vz="host">' + opcoes + "</select></div>" +
    '<div class="vz-f"><label for="vz-busca">Filtrar por CVE ou pacote</label><input id="vz-busca" class="vz-campo vz-busca" data-vz="busca" type="search" placeholder="Ex.: CVE-2024 ou openssl" autocomplete="off" value="' + esc(est.busca) + '"></div>' +
    '<label class="vz-tg"><input type="checkbox" role="switch" data-vz="corrig"' + (est.corrig ? " checked" : "") + '><span aria-hidden="true"></span>Só corrigíveis</label></div>' +
    (filtros.length ? '<div class="vz-filtros" aria-live="polite">' + filtros.join("") + "</div>" : "") +
    '<section class="vz-sec"><h3>' + icone("server") + 'Hosts</h3>' + quadroHosts + "</section>" +
    '<section class="vz-sec vz-so-largo"><h3>' + icone("bell") + "Pontos de atenção</h3>" + blocoAlertas + "</section>" +
    "</aside>" +
    '<main class="vz-main">' +
    bloco("Postura de segurança", postura, "vz-postura-c", '<span class="vz-tag">' + (ambiente ? "todos os hosts" : esc(est.host)) + "</span>", "shield") +
    bloco("Exposição corrigível", exposicao, "vz-expo", '<span class="vz-tag">período do painel</span>', "bug") +
    kpis +
    bloco("Composição", comp, "vz-comp", "", "wrench") +
    bloco("Hosts por CVEs corrigíveis", barrasHosts(sel), "vz-tophosts", '<span class="vz-tag">clique para filtrar</span>', "server") +
    bloco("CVEs de maior risco", tabelaCves(cves, ambiente), "vz-cves", '<span class="vz-tag">top ' + Math.min(TOP, cves.length) + " de " + fmt(cves.length) + "</span>", "bug") +
    bloco("Pacotes com mais CVEs", blocosPacotes(pacs), "vz-pacotes", '<span class="vz-tag">top ' + Math.min(12, pacs.length) + " de " + fmt(pacs.length) + "</span>", "wrench") +
    bloco("Mapa de calor por host", matriz, "vz-largo", '<span class="vz-tag">clique no host para filtrar</span>', "server") +
    '<section class="vz-card vz-so-estreito"><header><h3>' + icone("bell") + "Pontos de atenção</h3></header>" + blocoAlertas + "</section>" +
    '<footer class="vz-rod"><details><summary>Como o índice de saúde é calculado</summary><p>O índice parte de 100. Cada CVE Critical corrigível tira 20 pontos (máximo de 40), cada High tira 1,5 (máximo de 35) e cada Medium tira 0,3 (máximo de 10). Coleta com mais de 36 h tira 10, reboot pendente tira 5 e erro de coleta tira 20. Os rankings de CVEs e pacotes usam os 15 itens de maior risco de cada host.</p></details></footer>' +
    "</main></div></div>";

  // Gráfico medido após a inserção no DOM
  const alvo = raiz.querySelector('[data-chart="evol"]');
  const plotar = () => alvo && desenharLinhas(alvo, series.filter((s) => !est.hide[s.nome]), t0, t1);
  plotar();
  if (ro) ro.disconnect();
  if (alvo && window.ResizeObserver) {
    let w = alvo.clientWidth;
    ro = new ResizeObserver(() => { if (Math.abs(alvo.clientWidth - w) > 4) { w = alvo.clientWidth; plotar(); } });
    ro.observe(alvo);
  }

  // Eventos
  const q = (s) => raiz.querySelector(s);
  const foco = (s) => { const n = q(s); if (n) n.focus(); };
  q('[data-vz="host"]').addEventListener("change", (e) => { est.host = e.target.value; desenhar(); foco('[data-vz="host"]'); });
  q('[data-vz="corrig"]').addEventListener("change", (e) => { est.corrig = e.target.checked; desenhar(); foco('[data-vz="corrig"]'); });
  q('[data-vz="busca"]').addEventListener("input", (e) => {
    est.busca = e.target.value;
    clearTimeout(tBusca);
    tBusca = setTimeout(() => {
      const p = e.target.selectionStart; desenhar();
      const n = q('[data-vz="busca"]'); if (n) { n.focus(); n.setSelectionRange(p, p); }
    }, 250);
  });
  raiz.querySelectorAll("[data-host]").forEach((el) => el.addEventListener("click", () => {
    const h = el.getAttribute("data-host");
    est.host = est.host === h ? TODOS : h;
    desenhar();
    const n = raiz.querySelector('.vz-sq[data-host="' + CSS.escape(h) + '"]'); if (n) n.focus();
  }));
  raiz.querySelectorAll("[data-serie]").forEach((el) => el.addEventListener("click", () => {
    const s = el.getAttribute("data-serie");
    est.hide[s] = !est.hide[s];
    desenhar();
    const n = raiz.querySelector('[data-serie="' + s + '"]'); if (n) n.focus();
  }));
  raiz.querySelectorAll("[data-limpa]").forEach((el) => el.addEventListener("click", () => {
    const k = el.getAttribute("data-limpa");
    if (k === "host") est.host = TODOS; else if (k === "busca") est.busca = ""; else est.corrig = false;
    desenhar(); foco('[data-vz="host"]');
  }));
  relogio();
}

function relogio() {
  const el = raiz.querySelector('[data-vz="clock"]');
  if (el) el.textContent = new Date().toLocaleTimeString("pt-BR");
}

desenhar();
const timer = setInterval(relogio, 1000);
return () => { clearInterval(timer); clearTimeout(tBusca); if (ro) ro.disconnect(); };
