/* DomainExposure — interface monopage, JavaScript sans dépendance.
   Tout contenu provenant d'une source externe (noms de fuites, victimes de
   rançongiciels, en-têtes HTTP) est systématiquement échappé avant insertion :
   un outil de sécurité ne doit pas introduire lui-même une injection de code. */

const SEVERITIES = {
  critique: { label: "Critique", glyph: "◆", color: "var(--critique)", track: "var(--critique-track)", onLight: false },
  eleve:    { label: "Élevé",    glyph: "▲", color: "var(--eleve)",    track: "var(--eleve-track)",    onLight: true  },
  moyen:    { label: "Moyen",    glyph: "●", color: "var(--moyen)",    track: "var(--moyen-track)",    onLight: true  },
  faible:   { label: "Faible",   glyph: "▫", color: "var(--faible)",   track: "var(--faible-track)",   onLight: false },
  info:     { label: "Info",     glyph: "○", color: "var(--info)",     track: "var(--info-track)",     onLight: true  },
};
const SEVERITY_ORDER = ["critique", "eleve", "moyen", "faible", "info"];
const STATUS_LABELS = {
  ok: "exploité", partial: "partiellement exploité",
  skipped: "désactivé", error: "en échec",
};

const state = { modules: [], results: {}, analysisId: null, domain: null, selected: [] };

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function bandStyle(score) {
  if (score === null || score === undefined) return { color: "var(--info)", track: "var(--info-track)" };
  if (score >= 80) return { color: "var(--good)", track: "var(--good-track)" };
  if (score >= 70) return { color: "var(--moyen)", track: "var(--moyen-track)" };
  if (score >= 60) return { color: "var(--eleve)", track: "var(--eleve-track)" };
  return { color: "var(--critique)", track: "var(--critique-track)" };
}

function meter(score, style) {
  const s = style || bandStyle(score);
  return `<div class="meter" style="background:${s.track}">
    <div class="meter-fill" style="width:${Math.max(0, Math.min(100, score ?? 0))}%;background:${s.color}"></div>
  </div>`;
}

function severityBadge(code) {
  const meta = SEVERITIES[code] || SEVERITIES.info;
  return `<span class="whitespace-nowrap text-xs font-bold uppercase tracking-wide"
    style="color:${meta.color}">${meta.glyph} ${esc(meta.label)}</span>`;
}

/* ------------------------------------------------------------- thème ----- */
function initTheme() {
  const stored = localStorage.getItem("de-theme");
  if (stored) document.documentElement.setAttribute("data-theme", stored);
  $("theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark"
      || (!document.documentElement.getAttribute("data-theme")
          && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("de-theme", next);
  });
}

/* --------------------------------------------------------- progression --- */
function renderProgress() {
  $("progress-list").innerHTML = state.modules.map((module) => {
    const result = state.results[module.key];
    let mark = "<span class='muted'>en attente</span>";
    if (result === "running") mark = "<span style='color:var(--moyen)'>en cours…</span>";
    else if (result && typeof result === "object") {
      const label = STATUS_LABELS[result.status] || result.status;
      const color = result.status === "error" ? "var(--critique)"
        : result.status === "skipped" ? "var(--info)" : "var(--good)";
      mark = `<span style="color:${color}">${esc(label)}</span>`;
    }
    return `<div class="flex justify-between gap-2 rounded px-2 py-1"
      style="background:var(--surface-1)">
      <span>${esc(module.label)}</span>${mark}</div>`;
  }).join("");
}

/* ------------------------------------------------------------ résultats -- */
function renderResults(summary) {
  const modules = state.modules
    .map((module) => state.results[module.key])
    .filter((result) => result && typeof result === "object");

  const counts = Object.fromEntries(SEVERITY_ORDER.map((key) => [key, 0]));
  modules.forEach((module) => (module.findings || []).forEach((finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  const segments = SEVERITY_ORDER.filter((key) => counts[key] > 0).map((key) => ({
    key, meta: SEVERITIES[key], count: counts[key],
    share: total ? (counts[key] / total) * 100 : 0,
  }));

  const style = bandStyle(summary.score);
  const sorted = [...modules].sort(
    (a, b) => state.modules.findIndex((m) => m.key === a.key)
            - state.modules.findIndex((m) => m.key === b.key));

  const topFindings = modules.flatMap((m) => m.findings || [])
    .filter((f) => f.severity === "critique" || f.severity === "eleve")
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  $("results").classList.remove("hidden");
  $("results").innerHTML = `
    <div class="card rounded-lg p-5 mb-6">
      <div class="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div class="muted text-xs uppercase tracking-wider">Score global d'exposition</div>
          <div class="flex items-end gap-3">
            <div class="hero">${summary.score ?? "—"}<span class="text-base font-normal muted">/100</span></div>
            <div class="rounded-md px-3 py-1 text-xl font-semibold text-white"
                 style="background:${style.color}">${esc(summary.grade ?? "—")}</div>
          </div>
        </div>
        <div class="flex gap-2">
          <a class="card rounded-md px-3 py-1.5 text-xs" target="_blank" rel="noopener"
             href="/api/analyses/${encodeURIComponent(state.analysisId)}/report.html">Rapport HTML</a>
          <a class="card rounded-md px-3 py-1.5 text-xs"
             href="/api/analyses/${encodeURIComponent(state.analysisId)}/report.pdf">Rapport PDF</a>
        </div>
      </div>
      <div class="mt-3">${meter(summary.score, style)}</div>
      <p class="muted text-xs mt-2">${esc(state.domain || "")} — ${total} constat(s).
        ${summary.capped ? "Score plafonné par la présence d'au moins un constat critique." : ""}
        ${(summary.notes || []).map(esc).join(" ")}</p>

      <h3 class="text-sm font-semibold mt-5 mb-2">Répartition des constats par gravité</h3>
      ${segments.length ? `
      <div class="segbar">
        ${segments.map((s) => `<div style="width:${s.share}%;background:${s.meta.color};
          color:${s.meta.onLight ? "#0b0b0b" : "#fff"}" title="${esc(s.meta.label)} : ${s.count}">
          ${s.share >= 9 ? s.count : ""}</div>`).join("")}
      </div>
      <div class="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs muted">
        ${segments.map((s) => `<span class="inline-flex items-center gap-1.5">
          <span style="width:10px;height:10px;border-radius:2px;display:inline-block;
            background:${s.meta.color}"></span>${s.meta.glyph} ${esc(s.meta.label)}${s.share < 9 ? ` (${s.count})` : ""}
        </span>`).join("")}
      </div>` : `<p class="muted text-sm">Aucun constat.</p>`}

      <h3 class="text-sm font-semibold mt-5 mb-1">Score par module</h3>
      <div class="table-wrap"><table class="data" style="min-width:420px">
        <tbody>
        ${sorted.map((module) => {
          const ms = bandStyle(module.score);
          return `<tr>
            <td style="width:30%">${esc(module.label)}</td>
            <td>${module.score !== null && module.score !== undefined
              ? meter(module.score, ms)
              : `<span class="muted text-xs italic">${esc(module.disabled_reason || "non exploité")}</span>`}</td>
            <td class="num" style="width:10%"><strong>${module.score ?? "—"}</strong></td>
            <td class="num muted" style="width:12%">poids ${module.weight}</td>
          </tr>`;
        }).join("")}
        </tbody>
      </table></div>
    </div>

    ${topFindings.length ? `
    <div class="card rounded-lg p-5 mb-6">
      <h3 class="text-lg font-semibold mb-2">Priorités d'action</h3>
      <div class="table-wrap"><table class="data" style="min-width:560px">
        <thead><tr><th>Gravité</th><th>Constat</th><th>Recommandation</th></tr></thead>
        <tbody>${topFindings.map((f) => `<tr>
          <td>${severityBadge(f.severity)}</td>
          <td>${esc(f.title)}</td>
          <td>${esc(f.recommandation)}</td></tr>`).join("")}</tbody>
      </table></div>
    </div>` : ""}

    ${renderBusinessViews(sorted)}

    <div class="space-y-3">
      ${sorted.map(renderModuleCard).join("")}
    </div>`;
}

function renderPlan(plan) {
  if (!plan || !plan.etapes || !plan.etapes.length) return;
  const cible = $("plan");
  cible.classList.remove("hidden");
  const projection = plan.etapes.slice(0, 3);
  const apres = projection.length ? projection[projection.length - 1] : null;

  cible.innerHTML = `
    <h3 class="text-lg font-semibold mb-1">Plan de remédiation</h3>
    <p class="muted text-xs mb-3">Actions classées par gain de score et par effort.
      « Gain » = points apportés par l'action à ce stade du plan ; « score » = niveau atteint
      une fois cette action et les précédentes réalisées.</p>
    ${apres ? `<div class="rounded-md px-3 py-2 mb-3 text-sm"
       style="background:var(--good-track)">
      En traitant les ${projection.length} premières actions, le score passerait de
      <strong>${plan.score_actuel}/100 (${esc(plan.note_actuelle)})</strong> à
      <strong>${apres.score_cumule}/100 (${esc(apres.grade_cumule)})</strong>.
      Plan complet : <strong>${plan.score_projete}/100 (${esc(plan.note_projetee)})</strong>.
    </div>` : ""}
    <div class="table-wrap"><table class="data" style="min-width:620px">
      <thead><tr><th>#</th><th>Action</th><th>Module</th><th>Effort</th>
        <th class="num">Gain</th><th class="num">Score</th></tr></thead>
      <tbody>${plan.etapes.map((e, i) => `<tr>
        <td class="num muted">${i + 1}</td>
        <td><span style="color:${SEVERITIES[e.severity].color}">${SEVERITIES[e.severity].glyph}</span>
          ${esc(e.title)}<br><span class="muted text-xs">${esc(e.recommandation)}</span></td>
        <td>${esc(e.module_label)}</td>
        <td class="muted">${esc(e.effort_label)}</td>
        <td class="num" style="color:var(--good);font-weight:600">${e.gain_marginal > 0 ? "+" + e.gain_marginal : "—"}</td>
        <td class="num">${e.score_cumule} / ${esc(e.grade_cumule)}</td>
      </tr>`).join("")}</tbody>
    </table></div>
    ${plan.etapes_totales > plan.etapes.length
      ? `<p class="muted text-xs mt-2">${plan.etapes_totales} actions au total.</p>` : ""}`;
}

function renderBusinessViews(modules) {
  const byKey = Object.fromEntries(modules.map((m) => [m.key, m]));
  const timeline = byKey.breaches?.data?.chronologie || [];
  const addresses = byKey.exposure?.data?.adresses || [];
  const cveRows = addresses.filter((a) => (a.vulns || []).length);
  const subdomains = byKey.subdomains?.data?.records || [];
  if (!timeline.length && !cveRows.length && !subdomains.length) return "";

  return `<div class="card rounded-lg p-5 mb-6 space-y-5">
    ${timeline.length ? `
    <div>
      <h3 class="text-lg font-semibold mb-2">Chronologie des fuites</h3>
      <ul class="tl">${timeline.map((item) => `<li>
        <span class="font-semibold tabular-nums">${esc(item.date || "date inconnue")}</span> —
        <strong>${esc(item.nom)}</strong>
        ${item.comptes ? ` · ${Number(item.comptes).toLocaleString("fr-FR")} comptes` : ""}
        ${item.verifiee === false ? ` · <span class="muted">non confirmée</span>` : ""}
        ${(item.categories || []).length
          ? `<br><span class="muted text-xs">Catégories : ${esc((item.categories || []).join(", "))}</span>`
          : ""}
      </li>`).join("")}</ul>
    </div>` : ""}

    ${cveRows.length ? `
    <div>
      <h3 class="text-lg font-semibold mb-2">Vulnérabilités connues</h3>
      <div class="table-wrap"><table class="data" style="min-width:560px">
        <thead><tr><th>Adresse IP</th><th>Références CVE</th><th>Ports</th><th>Infrastructure</th></tr></thead>
        <tbody>${cveRows.map((row) => `<tr>
          <td>${esc(row.ip)}</td>
          <td>${esc((row.vulns || []).join(", "))}</td>
          <td>${esc((row.ports || []).join(", "))}</td>
          <td>${row.mutualisee ? "mutualisée — non imputable" : "dédiée"}</td>
        </tr>`).join("")}</tbody>
      </table></div>
    </div>` : ""}

    ${subdomains.length ? `
    <div>
      <h3 class="text-lg font-semibold mb-2">Sous-domaines (${subdomains.length})</h3>
      <div class="max-h-80 overflow-auto table-wrap">
      <table class="data" style="min-width:520px">
        <thead><tr><th>Nom</th><th>Adresses</th><th>Alias</th><th>État</th></tr></thead>
        <tbody>${subdomains.map((row) => `<tr>
          <td>${esc(row.name)}</td>
          <td>${esc((row.a || []).join(", ")) || "—"}</td>
          <td>${esc((row.cname || []).join(", ")) || "—"}</td>
          <td>${row.resolves ? "actif" : "ne résout plus"}</td>
        </tr>`).join("")}</tbody>
      </table></div>
    </div>` : ""}
  </div>`;
}

function renderModuleCard(module) {
  const findings = (module.findings || []).slice()
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const counts = SEVERITY_ORDER
    .map((key) => ({ key, n: findings.filter((f) => f.severity === key).length }))
    .filter((entry) => entry.n);

  return `<details class="card rounded-lg p-4" ${findings.some((f) =>
      f.severity === "critique" || f.severity === "eleve") ? "open" : ""}>
    <summary class="flex flex-wrap items-center justify-between gap-2">
      <span class="font-semibold">${esc(module.label)}</span>
      <span class="flex items-center gap-3 text-xs muted">
        ${counts.map((c) => `<span style="color:${SEVERITIES[c.key].color}">
          ${SEVERITIES[c.key].glyph} ${c.n}</span>`).join("")}
        <span>${module.score ?? "—"}/100</span>
        <span class="rounded-full px-2 py-0.5" style="border:1px solid var(--rule)">
          ${esc(STATUS_LABELS[module.status] || module.status)}</span>
      </span>
    </summary>
    <div class="mt-3 space-y-3">
      ${module.disabled_reason
        ? `<p class="muted text-sm italic">Module non exploité : ${esc(module.disabled_reason)}.</p>`
        : ""}
      ${findings.map((finding) => `
      <div class="rounded-md p-3" style="background:var(--surface-1);
           border-left:4px solid ${SEVERITIES[finding.severity].color}">
        <div class="flex flex-wrap items-baseline justify-between gap-2">
          <strong class="text-sm">${esc(finding.title)}</strong>
          ${severityBadge(finding.severity)}
        </div>
        <dl class="mt-2 text-sm space-y-1">
          <dt class="muted text-xs uppercase tracking-wide">Constat</dt>
          <dd>${esc(finding.constat)}</dd>
          <dt class="muted text-xs uppercase tracking-wide">Ce que cela signifie</dt>
          <dd>${esc(finding.explication)}</dd>
          <dt class="muted text-xs uppercase tracking-wide">Recommandation</dt>
          <dd>${esc(finding.recommandation)}</dd>
        </dl>
        ${(finding.references || []).length ? `<p class="muted text-xs mt-2">
          Références : ${finding.references.map((r) =>
            `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">
              ${esc(r.framework)} — ${esc(r.label)}</a>`).join(" · ")}</p>` : ""}
        <p class="muted text-xs mt-1 font-mono">${esc(finding.code)}</p>
      </div>`).join("")}
      ${!findings.length && !module.disabled_reason
        ? `<p class="muted text-sm italic">Aucun constat.</p>` : ""}
      ${(module.errors || []).length ? `<div class="muted text-xs">
        <strong>Limites rencontrées :</strong>
        <ul class="list-disc pl-4">${module.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
      </div>` : ""}
    </div>
  </details>`;
}

/* ----------------------------------------------------------- portefeuille - */
function tendanceHtml(valeur) {
  if (valeur === null || valeur === undefined || valeur === 0) {
    return `<span class="muted">—</span>`;
  }
  const hausse = valeur > 0;
  return `<span style="color:${hausse ? "var(--good)" : "var(--critique)"};font-weight:600"
    title="${hausse ? "Amélioration" : "Dégradation"} depuis l'analyse précédente">
    ${hausse ? "▲ +" : "▼ "}${valeur}</span>`;
}

function dateCourte(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString("fr-FR",
    { day: "2-digit", month: "2-digit", year: "2-digit" });
}

async function loadPortefeuille() {
  let payload;
  try {
    const reponse = await fetch("/api/watchlist");
    if (!reponse.ok) return;
    payload = await reponse.json();
  } catch (exc) { return; }

  const o = payload.ordonnanceur;
  $("ordonnanceur").textContent = o.actif
    ? `Ordonnanceur actif · vérification toutes les ${Math.round(o.periode_secondes / 60)} min` +
      ` · alerte dès -${o.seuil_alerte_points} points` +
      (o.courriel_configure ? " · courriel configuré" : " · webhook uniquement")
    : "Ordonnanceur désactivé (SCHEDULER_ENABLED)";

  const lignes = payload.domaines;
  if (!lignes.length) {
    $("portefeuille").innerHTML =
      `<p class="muted text-sm italic">Aucun domaine suivi pour le moment.</p>`;
    return;
  }

  $("portefeuille").innerHTML = `<div class="table-wrap"><table class="data" style="min-width:720px">
    <thead><tr><th>Client</th><th>Domaine</th><th>Score</th><th class="num">Note</th>
      <th class="num">Tendance</th><th>Constats</th><th>Dernière</th><th>Prochaine</th>
      <th></th></tr></thead>
    <tbody>${lignes.map((l) => {
      const style = bandStyle(l.score);
      const graves = (l.constats.critique || 0) + (l.constats.eleve || 0);
      return `<tr${l.actif ? "" : ' style="opacity:.55"'}>
        <td><strong>${esc(l.client)}</strong>${l.actif ? "" : " <span class='muted'>(en pause)</span>"}</td>
        <td class="muted">${esc(l.domaine)}</td>
        <td style="min-width:110px">${l.score === null ? '<span class="muted text-xs">jamais analysé</span>'
          : meter(l.score, style) + `<span class="muted text-xs">${l.score}/100</span>`}</td>
        <td class="num"><strong>${esc(l.note || "—")}</strong></td>
        <td class="num">${tendanceHtml(l.tendance)}</td>
        <td>${graves
          ? `<span style="color:${SEVERITIES.critique.color}">◆ ${l.constats.critique || 0}</span>
             <span style="color:${SEVERITIES.eleve.color}">▲ ${l.constats.eleve || 0}</span>`
          : '<span class="muted">—</span>'}</td>
        <td class="muted">${dateCourte(l.derniere_analyse)}</td>
        <td class="muted">${l.intervalle_heures ? dateCourte(l.prochaine_analyse) : "manuel"}</td>
        <td class="whitespace-nowrap">
          <button class="pf-run card rounded px-2 py-1 text-xs" data-id="${esc(l.id)}"
                  title="Analyser maintenant">Analyser</button>
          <button class="pf-del card rounded px-2 py-1 text-xs" data-id="${esc(l.id)}"
                  data-client="${esc(l.client)}" title="Retirer du portefeuille">Retirer</button>
        </td>
      </tr>`;
    }).join("")}</tbody></table></div>`;

  document.querySelectorAll(".pf-run").forEach((bouton) =>
    bouton.addEventListener("click", async () => {
      bouton.disabled = true;
      bouton.textContent = "Analyse…";
      await fetch(`/api/watchlist/${encodeURIComponent(bouton.dataset.id)}/run`,
                  { method: "POST" });
      await loadPortefeuille();
      await loadHistory(null);
    }));

  document.querySelectorAll(".pf-del").forEach((bouton) =>
    bouton.addEventListener("click", async () => {
      if (!confirm(`Retirer « ${bouton.dataset.client} » du portefeuille ? `
          + `Le mandat est révoqué et les analyses planifiées cessent.`)) return;
      await fetch(`/api/watchlist/${encodeURIComponent(bouton.dataset.id)}`, { method: "DELETE" });
      await loadPortefeuille();
    }));
}

async function ajouterAuPortefeuille() {
  const erreur = $("w-error");
  erreur.classList.add("hidden");
  const corps = {
    domain: $("w-domain").value.trim(),
    label: $("w-label").value.trim() || null,
    interval_hours: Number($("w-interval").value),
    authorization: $("w-auth").checked,
    passive_only: $("w-passive").checked,
    domain_verified: $("w-verified").checked,
    mandate_reference: $("w-reference").value.trim() || null,
    notify_webhook: $("w-webhook").value.trim() || null,
    notify_email: $("w-email").value.trim() || null,
  };
  if (!corps.authorization || !corps.passive_only) {
    erreur.textContent = "Les deux attestations obligatoires valent mandat permanent : "
      + "elles doivent être cochées.";
    erreur.classList.remove("hidden");
    return;
  }
  const reponse = await fetch("/api/watchlist", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(corps),
  });
  const payload = await reponse.json().catch(() => ({}));
  if (!reponse.ok) {
    const detail = payload.detail || {};
    erreur.textContent = [detail.erreur || "Inscription refusée.", detail.aide]
      .filter(Boolean).join(" ");
    erreur.classList.remove("hidden");
    return;
  }
  ["w-domain", "w-label", "w-reference", "w-webhook", "w-email"].forEach((id) => ($(id).value = ""));
  $("w-auth").checked = $("w-passive").checked = $("w-verified").checked = false;
  await loadPortefeuille();
}

/* ------------------------------------------------------------ historique - */
async function loadHistory(domain) {
  const url = domain ? `/api/analyses?domain=${encodeURIComponent(domain)}` : "/api/analyses";
  const response = await fetch(url);
  if (!response.ok) return;
  const { analyses } = await response.json();
  if (!analyses.length) { $("history").classList.add("hidden"); return; }

  $("history").classList.remove("hidden");
  $("history-list").innerHTML = `<div class="table-wrap"><table class="data" style="min-width:560px">
    <thead><tr><th></th><th>Date</th><th>Domaine</th><th class="num">Score</th>
      <th>Note</th><th>Opérateur</th></tr></thead>
    <tbody>${analyses.map((row) => `<tr>
      <td><input type="checkbox" class="hist" value="${esc(row.id)}"
           data-domain="${esc(row.domain)}"></td>
      <td>${esc(new Date(row.started_at).toLocaleString("fr-FR"))}</td>
      <td>${esc(row.domain)}</td>
      <td class="num">${row.score ?? "—"}</td>
      <td>${esc(row.grade || "—")}</td>
      <td class="muted">${esc(row.actor || "")}</td>
    </tr>`).join("")}</tbody></table></div>`;

  document.querySelectorAll(".hist").forEach((box) => box.addEventListener("change", () => {
    state.selected = [...document.querySelectorAll(".hist:checked")].map((b) => b.value);
    $("compare").disabled = state.selected.length !== 2;
  }));
}

async function runComparison() {
  const [a, b] = state.selected;
  const response = await fetch(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
  const payload = await response.json();
  if (!response.ok) {
    $("comparison").innerHTML = `<p style="color:var(--critique)">
      ${esc(payload.detail?.erreur || "Comparaison impossible.")}</p>`;
    return;
  }
  const delta = payload.delta_score;
  const sign = delta > 0 ? "+" : "";
  const color = delta > 0 ? "var(--good)" : delta < 0 ? "var(--critique)" : "var(--info)";
  $("comparison").innerHTML = `
    <div class="rounded-md p-3" style="background:var(--surface-1)">
      <p class="text-sm"><strong>${esc(payload.domaine)}</strong> —
        ${esc(new Date(payload.avant.date).toLocaleDateString("fr-FR"))}
        (${payload.avant.score ?? "—"}/${esc(payload.avant.note || "—")}) →
        ${esc(new Date(payload.apres.date).toLocaleDateString("fr-FR"))}
        (${payload.apres.score ?? "—"}/${esc(payload.apres.note || "—")})
        <span style="color:${color};font-weight:600"> ${delta === null ? "" : sign + delta} points</span>
      </p>
      <p class="muted text-xs mt-1">${payload.resume.apparus} constat(s) apparu(s) ·
        ${payload.resume.resolus} résolu(s) · ${payload.resume.persistants} persistant(s)</p>
      ${payload.findings_apparus.length ? `<p class="text-sm mt-2"><strong>Apparus :</strong></p>
        <ul class="list-disc pl-5 text-sm">${payload.findings_apparus.map((f) =>
          `<li>${severityBadge(f.severity)} ${esc(f.title)}</li>`).join("")}</ul>` : ""}
      ${payload.findings_resolus.length ? `<p class="text-sm mt-2"><strong>Résolus :</strong></p>
        <ul class="list-disc pl-5 text-sm">${payload.findings_resolus.map((f) =>
          `<li>${severityBadge(f.severity)} ${esc(f.title)}</li>`).join("")}</ul>` : ""}
    </div>`;
}

/* --------------------------------------------------------------- analyse - */
async function launch() {
  const domain = $("domain").value.trim();
  const payload = {
    domain,
    authorization: $("c-auth").checked,
    passive_only: $("c-passive").checked,
    domain_verified: $("c-verified").checked,
  };
  const error = $("form-error");
  error.classList.add("hidden");

  if (!payload.authorization || !payload.passive_only) {
    error.textContent = "Les deux cases obligatoires doivent être cochées avant toute analyse.";
    error.classList.remove("hidden");
    return;
  }

  $("launch").disabled = true;
  state.results = {};
  $("results").classList.add("hidden");
  $("plan").classList.add("hidden");
  $("comparison").innerHTML = "";

  let response;
  try {
    response = await fetch("/api/analyses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (exc) {
    error.textContent = "Le serveur est injoignable.";
    error.classList.remove("hidden");
    $("launch").disabled = false;
    return;
  }

  const body = await response.json();
  if (!response.ok) {
    const detail = body.detail || {};
    error.textContent = [detail.erreur || "Demande refusée.", detail.aide].filter(Boolean).join(" ");
    error.classList.remove("hidden");
    $("launch").disabled = false;
    return;
  }

  state.analysisId = body.id;
  state.domain = body.domaine_unicode || body.domaine;
  $("progress").classList.remove("hidden");
  $("progress-meta").textContent = state.domain;

  const source = new EventSource(body.flux);
  source.addEventListener("analysis_started", (event) => {
    const data = JSON.parse(event.data);
    state.modules = data.modules;
    $("progress-meta").textContent =
      `${state.domain} — résolution DNS : ${data.dns_backend}`;
    renderProgress();
  });
  source.addEventListener("recon", (event) => {
    const data = JSON.parse(event.data);
    if (!data.resolves) {
      $("progress-meta").textContent += " — le domaine ne résout pas";
    }
  });
  source.addEventListener("module_started", (event) => {
    state.results[JSON.parse(event.data).key] = "running";
    renderProgress();
  });
  source.addEventListener("module_done", (event) => {
    const data = JSON.parse(event.data);
    state.results[data.key] = data.result;
    renderProgress();
  });
  source.addEventListener("analysis_done", async (event) => {
    renderResults(JSON.parse(event.data));
    $("launch").disabled = false;
    source.close();
    loadHistory(null);
    loadPortefeuille();
    try {
      const reponse = await fetch(
        `/api/analyses/${encodeURIComponent(state.analysisId)}/plan?limite=12`);
      if (reponse.ok) renderPlan(await reponse.json());
    } catch (exc) {
      /* le plan est un confort : son absence ne doit pas masquer les résultats */
    }
  });
  source.addEventListener("analysis_failed", (event) => {
    const data = JSON.parse(event.data);
    error.textContent = `L'analyse a échoué : ${data.erreur}`;
    error.classList.remove("hidden");
    $("launch").disabled = false;
    source.close();
  });
  source.onerror = () => {
    source.close();
    $("launch").disabled = false;
  };
}

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  $("launch").addEventListener("click", launch);
  $("domain").addEventListener("keydown", (event) => {
    if (event.key === "Enter") launch();
  });
  $("compare").addEventListener("click", runComparison);
  $("w-add").addEventListener("click", ajouterAuPortefeuille);
  loadHistory(null);
  loadPortefeuille();
});
