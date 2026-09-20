/* Ligolo pivot panel (v7.2) — cockpit control for the ligolo-ng daemon.
 * Talks to /api/ligolo/* (dashboard/blueprints/ligolo.py), which proxies
 * the ligolo-ng daemon REST API on 127.0.0.1:11602. */
"use strict";

function _ligoloBanner(msg, isError) {
    const el = document.getElementById("ligolo-banner");
    if (!el) return;
    el.textContent = msg;
    el.classList.remove("hidden");
    el.classList.toggle("mech-banner-error", !!isError);
    if (!isError) {
        clearTimeout(ligolo._bannerTimer);
        ligolo._bannerTimer = setTimeout(() => el.classList.add("hidden"), 5000);
    }
}

async function _ligoloApi(method, path, body) {
    const opts = {method, headers: {}};
    if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    const data = await resp.json().catch(() => ({ok: false, error: "bad JSON"}));
    if (!resp.ok || data.ok === false) {
        throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
}

const ligolo = {
    _bannerTimer: null,
    _agents: {},

    async refresh() {
        try {
            const {status} = await _ligoloApi("GET", "/api/ligolo/status");
            this.renderStatus(status);
            if (status.running) await this.refreshAgents();
        } catch (e) {
            _ligoloBanner("status failed: " + e.message, true);
        }
    },

    renderStatus(status) {
        const stateEl = document.getElementById("ligolo-daemon-state");
        if (stateEl) {
            stateEl.textContent = status.running
                ? `● running (pid ${status.pid}, agents: ${Object.keys(status.agents || {}).length})`
                : "○ stopped";
        }
        const startBtn = document.getElementById("ligolo-start-btn");
        const stopBtn = document.getElementById("ligolo-stop-btn");
        if (startBtn) startBtn.disabled = !!status.running;
        if (stopBtn) stopBtn.disabled = !status.running;
    },

    async refreshAgents() {
        const holder = document.getElementById("ligolo-agents");
        if (!holder) return;
        try {
            const {agents} = await _ligoloApi("GET", "/api/ligolo/agents");
            this._agents = agents || {};
            this.renderAgents();
        } catch (e) {
            holder.innerHTML = `<p class="muted">agents unavailable: ${e.message}</p>`;
        }
    },

    renderAgents() {
        const holder = document.getElementById("ligolo-agents");
        const tunnelHolder = document.getElementById("ligolo-tunnels");
        if (!holder || !tunnelHolder) return;
        const ids = Object.keys(this._agents);
        if (!ids.length) {
            holder.innerHTML = "<p class='muted'>No agents connected. Run on a target: agent -connect &lt;this-host&gt;:11601 -ignore-cert</p>";
            tunnelHolder.innerHTML = "";
            return;
        }
        holder.innerHTML = ids.map(id => {
            const a = this._agents[id];
            const tun = a.Running ? "🟢 tunnel up" : "⚪ tunnel down";
            const btn = a.Running
                ? `<button onclick="ligoloTunnelStop(${id})">⏹ Stop tunnel</button>`
                : `<button onclick="ligoloTunnelStart(${id})">▶ Start tunnel</button>`;
            return `<div class="mech-target-row">${id} · ${a.Name} · session ${a.SessionID} · ${tun} ${btn}</div>`;
        }).join("");
        tunnelHolder.innerHTML = `<p class="muted">TUN traffic reaches the agent's loopback at 240.0.0.1 once the tunnel is up; add agent-side subnets as routes below.</p>`;
    },

    async daemonStart() {
        try {
            const {status} = await _ligoloApi("POST", "/api/ligolo/daemon/start", {});
            _ligoloBanner("ligolo daemon started");
            this.renderStatus(status);
            await this.refreshAgents();
        } catch (e) {
            _ligoloBanner("start failed: " + e.message, true);
        }
        this.refresh();
    },

    async daemonStop() {
        try {
            await _ligoloApi("POST", "/api/ligolo/daemon/stop");
            _ligoloBanner("ligolo daemon stopped");
            document.getElementById("ligolo-agents").innerHTML =
                "<p class='muted'>Daemon stopped.</p>";
            document.getElementById("ligolo-tunnels").innerHTML = "";
        } catch (e) {
            _ligoloBanner("stop failed: " + e.message, true);
        }
        this.refresh();
    },

    async tunnelStart(agentId) {
        try {
            await _ligoloApi("POST", "/api/ligolo/tunnel/start", {agent_id: agentId});
            _ligoloBanner(`tunnel starting for agent ${agentId} (TUN 'ligolo')`);
        } catch (e) {
            _ligoloBanner(`tunnel start failed: ${e.message} (TUN creation needs root — run the dashboard with elevated privileges for pivoting)`, true);
        }
        this.refresh();
    },

    async tunnelStop(agentId) {
        try {
            await _ligoloApi("POST", "/api/ligolo/tunnel/stop", {agent_id: agentId});
            _ligoloBanner(`tunnel stopping for agent ${agentId}`);
        } catch (e) {
            _ligoloBanner("tunnel stop failed: " + e.message, true);
        }
        this.refresh();
    },

    async addRoute() {
        const input = document.getElementById("ligolo-route-input");
        const route = (input && input.value || "").trim();
        if (!route) { _ligoloBanner("enter a CIDR first", true); return; }
        const upAgent = Object.entries(this._agents).find(([, a]) => a.Running);
        const iface = (upAgent && upAgent[1].Interface) || "ligolo";
        try {
            await _ligoloApi("POST", "/api/ligolo/route",
                             {interface: iface, route});
            _ligoloBanner(`route ${route} → ${iface}`);
            if (input) input.value = "";
        } catch (e) {
            _ligoloBanner("route failed: " + e.message, true);
        }
    },
};

function ligoloRefresh()        { ligolo.refresh(); }
function ligoloDaemonStart()    { ligolo.daemonStart(); }
function ligoloDaemonStop()     { ligolo.daemonStop(); }
function ligoloTunnelStart(id)  { ligolo.tunnelStart(id); }
function ligoloTunnelStop(id)   { ligolo.tunnelStop(id); }
function ligoloAddRoute()       { ligolo.addRoute(); }

document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("ligolo-agents")) ligolo.refresh();
});
