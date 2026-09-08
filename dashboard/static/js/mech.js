/**
 * RedTeam Harness — Mech-Unit cockpit module (v7.0 P4.3–P4.6)
 *
 * Point-and-click flow: TARGETS (scan → click) → INTENT WALL (probe-annotated
 * cards → click) → RUN CONSOLE (preview → run → live steps → next moves).
 * Vanilla JS, no build step, no CDN. Socket channels: mech_* (see
 * core/mech/events.py for the canonical mapping).
 */

const mechState = {
    intents: [],
    selectedTarget: null,   // {bssid, essid, channel, ...}
    selectedIntent: null,   // intent id
    currentPlan: null,      // compiled plan dict
    planState: 'idle',
};

// ── helpers ──────────────────────────────────────────────────────────
function mechEl(id) { return document.getElementById(id); }

async function mechFetch(url, opts) {
    const res = await fetch(url, opts);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || res.statusText);
    return body;
}

// Inline dismissible banner — replaces blocking alert() popups (v7.1).
function mechBanner(msg, kind) {
    const box = mechEl('mech-banner');
    if (!box) { console.warn('mech:', msg); return; }
    box.className = `mech-banner ${kind || 'info'}`;
    box.innerHTML = `<span>${msg}</span> <button class="tab" onclick="mechHideBanner()">✕</button>`;
    box.classList.remove('hidden');
}

function mechHideBanner() {
    const box = mechEl('mech-banner');
    if (box) box.classList.add('hidden');
}

// ── section 1: targets ───────────────────────────────────────────────
async function mechScanTargets() {
    const box = mechEl('mech-targets');
    box.innerHTML = '<p class="muted">Scanning… (airodump sweep, ~10s)</p>';
    try {
        const body = await mechFetch('/api/mech/targets/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({duration: 10}),
        });
        mechRenderTargets(body.targets || []);
    } catch (err) {
        box.innerHTML = `<p class="muted">Scan unavailable: ${err.message}</p>`;
    }
}

function mechRenderTargets(targets) {
    mechState._lastTargets = targets || [];
    const box = mechEl('mech-targets');
    if (!targets.length) {
        box.innerHTML = '<p class="muted">No APs found. Check the capture interface and scan again.</p>';
        return;
    }
    const rows = targets.map(t => `
        <div class="mech-target ${mechState.selectedTarget?.bssid === t.bssid ? 'selected' : ''}"
             onclick="mechSelectTarget('${t.bssid}')">
            <strong>${t.essid || '(hidden)'}</strong>
            <span class="muted">${t.bssid} · ch ${t.channel || '?'} · ${t.encryption || '?'} · ${t.power} dBm</span>
        </div>`).join('');
    box.innerHTML = rows;
}

function mechSelectTarget(bssid) {
    mechState.selectedTarget = (mechState._lastTargets || [])
        .find(t => t.bssid === bssid) || {bssid};
    mechRenderTargets(mechState._lastTargets || []);
}

// ── section 2: intent wall ───────────────────────────────────────────
async function mechLoadIntents() {
    try {
        const body = await mechFetch('/api/mech/intents');
        mechState.intents = body.intents || [];
        // Probe every intent for greying (parallel, quiet).
        await Promise.all(mechState.intents.map(async card => {
            try {
                const p = await mechFetch(`/api/mech/intents/${card.id}/probe`);
                card.probes = p.probes || [];
                card.ready = card.probes.every(x => x.ok);
            } catch (err) {
                card.probes = [];
                card.ready = false;
            }
        }));
        mechRenderIntents();
    } catch (err) {
        mechEl('mech-intents').innerHTML = `<p class="muted">Intents unavailable: ${err.message}</p>`;
    }
}

function mechRenderIntents() {
    const box = mechEl('mech-intents');
    const cards = mechState.intents.map(card => {
        const missing = (card.probes || []).filter(p => !p.ok)
            .flatMap(p => p.missing || []);
        const noiseBar = {silent: '▢', low: '▫', medium: '▯', high: '▮'}[card.noise] || '▫';
        return `
        <div class="mech-card ${card.ready ? '' : 'disabled'} ${mechState.selectedIntent === card.id ? 'selected' : ''}"
             onclick="${card.ready ? `mechSelectIntent('${card.id}')` : `mechShowBlocked('${card.id}')`}">
            <div class="mech-card-title">${card.operator_label}</div>
            <div class="mech-card-outcome muted">${card.outcome}</div>
            <div class="mech-card-meta muted">
                noise ${noiseBar} · ${card.time_to_impact} · ${card.steps.length} steps
            </div>
            ${missing.length ? `<div class="mech-card-missing">missing: ${missing.join(', ')}</div>` : ''}
        </div>`;
    }).join('');
    box.innerHTML = cards || '<p class="muted">No intents loaded.</p>';
}

function mechShowBlocked(intentId) {
    const card = mechState.intents.find(c => c.id === intentId);
    const missing = (card?.probes || []).filter(p => !p.ok)
        .map(p => `${p.reason} — fix: ${p.fix}`).join('; ');
    mechBanner(`Intent "${card?.operator_label}" is not available on this host: ${missing || 'probe failed'}`, 'warn');
}

// ── section 3: run console ───────────────────────────────────────────
async function mechSelectIntent(intentId) {
    mechState.selectedIntent = intentId;
    mechRenderIntents();
    const preview = mechEl('mech-plan-preview');
    preview.innerHTML = '<p class="muted">Compiling plan…</p>';
    try {
        const payload = {intent_id: intentId};
        if (mechState.selectedTarget) {
            payload.target = {
                bssid: mechState.selectedTarget.bssid || '',
                essid: mechState.selectedTarget.essid || '',
            };
        }
        const plan = await mechFetch('/api/mech/plan/compile', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        mechState.currentPlan = plan;
        mechRenderPlanPreview(plan);
        mechEl('mech-run-controls').classList.remove('hidden');
        mechSetPlanState('compiled');
    } catch (err) {
        preview.innerHTML = `<p class="muted">Compile blocked: ${err.message}</p>`;
        mechEl('mech-run-controls').classList.add('hidden');
    }
}

function mechRenderPlanPreview(plan) {
    const rows = plan.steps.map((s, i) => `
        <div class="mech-step" id="mech-step-${s.step}">
            <span class="mech-step-num">${i + 1}</span>
            <strong>${s.step}</strong>
            <span class="muted">${s.tool}</span>
            <code class="mech-step-args">${JSON.stringify(s.args)}</code>
            ${s.gate ? `<span class="mech-gate">gate: ${s.gate.output || (s.gate.file || []).join(',') || s.gate.exit_code}</span>` : ''}
        </div>`).join('');
    const unresolved = (plan.unresolved || []).map(u =>
        `<div class="mech-card-missing">needs input: ${u.step}.${u.arg} (${u.placeholder})</div>`).join('');
    mechEl('mech-plan-preview').innerHTML = `
        <div class="muted">plan ${plan.plan_id} · target ${plan.target.bssid || plan.target.host || '(none)'}
             · every param's source is in the tooltip</div>
        ${rows}${unresolved}`;
}

async function mechRunPlan() {
    if (!mechState.currentPlan) return;
    try {
        await mechFetch(`/api/mech/plan/${mechState.currentPlan.plan_id}/run`, {method: 'POST'});
        mechSetPlanState('running');
    } catch (err) {
        mechBanner(`Run failed: ${err.message}`, 'error');
    }
}

async function mechResumePlan() {
    if (!mechState.currentPlan) return;
    try {
        await mechFetch(`/api/mech/plan/${mechState.currentPlan.plan_id}/resume`, {method: 'POST'});
        mechSetPlanState('running');
    } catch (err) {
        mechBanner(`Resume failed: ${err.message}`, 'error');
    }
}

async function mechPausePlan() {
    if (!mechState.currentPlan) return;
    await mechFetch(`/api/mech/plan/${mechState.currentPlan.plan_id}/pause`, {method: 'POST'});
    mechSetPlanState('pausing…');
}

async function mechAbortPlan() {
    if (!mechState.currentPlan) return;
    await mechFetch(`/api/mech/plan/${mechState.currentPlan.plan_id}/abort`, {method: 'POST'});
    mechSetPlanState('aborting…');
}

function mechSetPlanState(state) {
    mechState.planState = state;
    mechEl('mech-plan-state').textContent = `state: ${state}`;
    // Busy-state: no double-run, pause/abort only while something is live.
    const busy = ['running', 'pausing…', 'aborting…'].includes(state);
    const runBtn = mechEl('mech-run-btn');
    const pauseBtn = mechEl('mech-pause-btn');
    const abortBtn = mechEl('mech-abort-btn');
    if (runBtn) {
        runBtn.disabled = busy;
        const resumeMode = state === 'paused';
        runBtn.textContent = resumeMode ? '▶ Resume' : '▶ Run';
        runBtn.setAttribute('onclick', resumeMode ? 'mechResumePlan()' : 'mechRunPlan()');
    }
    if (pauseBtn) pauseBtn.disabled = !busy;
    if (abortBtn) abortBtn.disabled = !busy;
}

// ── persisted plans: reattach after a refresh (v7.1) ────────────────
async function mechLoadPlans() {
    try {
        const body = await mechFetch('/api/mech/plans');
        mechRenderPlans(body.plans || []);
    } catch (err) { /* quiet — the reattach list is advisory */ }
}

function mechRenderPlans(plans) {
    const box = mechEl('mech-plans');
    if (!box) return;
    if (!plans.length) { box.innerHTML = ''; return; }
    const badge = s => ({running: '🟢', paused: '🟡', done: '✅',
                         failed: '❌', aborted: '⛔', compiled: '⚪'}[s] || '⚪');
    box.innerHTML = '<h4>Plans on this host</h4>' + plans.slice(0, 8).map(p => `
        <div class="mech-plan-row">
            <span>${badge(p.state)} ${p.plan_id}</span>
            <span class="muted">${p.intent_id} · ${p.steps_done}/${p.steps_total} steps</span>
            <button class="tab" onclick="mechReattach('${p.plan_id}')">REATTACH</button>
        </div>`).join('');
}

async function mechReattach(planId) {
    try {
        const plan = await mechFetch(`/api/mech/plan/${planId}`);
        const st = await mechFetch(`/api/mech/plan/${planId}/status`).catch(() => null);
        mechState.currentPlan = plan;
        mechRenderPlanPreview(plan);
        mechEl('mech-run-controls').classList.remove('hidden');
        mechSetPlanState(st ? st.state : 'unknown');
        mechLoadNextMoves();
    } catch (err) {
        mechBanner(`Reattach failed: ${err.message}`, 'error');
    }
}

// ── SocketIO streaming (mech_* channels) ─────────────────────────────
function initMechSocket(socket) {
    socket.on('mech_step_started', (d) => {
        if (d.plan_id !== mechState.currentPlan?.plan_id) return;
        const el = mechEl(`mech-step-${d.step}`);
        if (el) el.classList.add('running');
    });
    socket.on('mech_step_complete', (d) => {
        if (d.plan_id !== mechState.currentPlan?.plan_id) return;
        const el = mechEl(`mech-step-${d.step}`);
        if (el) { el.classList.remove('running'); el.classList.add('success'); }
        if (d.finding) mechAppendNextMovesNote(`✔ ${d.step}: ${d.finding}`);
    });
    socket.on('mech_step_failed', (d) => {
        if (d.plan_id !== mechState.currentPlan?.plan_id) return;
        const el = mechEl(`mech-step-${d.step}`);
        if (el) { el.classList.remove('running'); el.classList.add('failed'); }
    });
    socket.on('mech_plan_state', (d) => {
        if (d.plan_id !== mechState.currentPlan?.plan_id) return;
        mechSetPlanState(d.state);
        if (d.state === 'done' || d.state === 'failed') mechLoadNextMoves();
    });
    socket.on('mech_next_moves', (d) => mechRenderNextMoves(d.moves || []));
}

function mechAppendNextMovesNote(text) {
    const box = mechEl('mech-next-moves');
    const note = document.createElement('div');
    note.className = 'muted';
    note.textContent = text;
    box.appendChild(note);
}

async function mechLoadNextMoves() {
    if (!mechState.currentPlan) return;
    try {
        const body = await mechFetch(`/api/mech/plan/${mechState.currentPlan.plan_id}/next-moves`);
        mechRenderNextMoves(body.moves || []);
    } catch (err) { /* quiet — next moves are advisory */ }
}

function mechRenderNextMoves(moves) {
    const box = mechEl('mech-next-moves');
    if (!moves.length) { box.innerHTML = ''; return; }
    const rows = moves.map(m => `
        <div class="mech-move ${m.score <= 0 ? 'muted' : ''}">
            <button onclick="mechSelectIntent('${m.intent}')">➜ ${m.intent}</button>
            <span class="muted">score ${m.score.toFixed(2)} · ${m.why}</span>
        </div>`).join('');
    box.innerHTML = `<h4>Next moves (VULN-GRAPH)</h4>${rows}`;
}

// ── boot ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    if (!mechEl('mech-console')) return;   // panel absent → no-op
    mechLoadIntents();
    mechLoadPlans();
    const origShowTab = window.showResultsTab;
    if (origShowTab) {
        window.showResultsTab = function(tab) {
            origShowTab(tab);
            if (tab === 'mech') { mechLoadIntents(); mechLoadPlans(); }
        };
    }
    if (window.socket) initMechSocket(window.socket);
});
