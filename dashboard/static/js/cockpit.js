/**
 * RedTeam Harness — Cockpit Dashboard v2.0
 * Real-time WebSocket: streaming, plan, autonomous, token tracking, reports
 */

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════
let socket = null;
let sessionId = null;
let toolCount = 0;
let stepCount = 0;
let commandLog = [];
let findings = [];
let currentCategory = 'all';
let streamingMessage = null;
let autonomousEnabled = false;

// ═══════════════════════════════════════════════════════════════
// Initialize
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    loadTools();
    loadQuickCommands();
    loadAttackChains();
    loadWorkflows();
    populateGraphSelect();
    loadStatus();
    loadSessions();
    loadSafety();
    initInput();
    initTabs();
    initAutonomousToggle();
});

// ═══════════════════════════════════════════════════════════════
// WebSocket
// ═══════════════════════════════════════════════════════════════
function initSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to RedTeam Harness v2');
        updateLLMStatus(true);
    });

    socket.on('disconnect', () => updateLLMStatus(false));

    socket.on('status', (data) => {
        updateStatusIndicators(data);
        updateTokenUsage(data.token_usage);
    });

    // ── Tool events ──
    socket.on('tool_start', (data) => {
        addToolMessage(data.tool, data.args, 'running');
    });

    socket.on('tool_complete', (data) => {
        toolCount++;
        updateMeta();
        updateToolResult(data);
        appendLiveOutput(data);
        addCommandToLog(data);
    });

    // ── LLM streaming ──
    socket.on('llm_thinking', () => showThinking(true));

    socket.on('llm_chunk', (data) => {
        if (!streamingMessage) {
            streamingMessage = addAssistantMessageStream();
        }
        appendToStreamingMessage(data.content);
    });

    socket.on('llm_response', (data) => {
        showThinking(false);
        finalizeStreamingMessage();
    });

    // ── Plan & Report ──
    socket.on('plan_generated', (data) => {
        showPlan(data.plan);
    });

    socket.on('report_generated', (data) => {
        showReport(data.report);
    });

    // ── Task lifecycle ──
    socket.on('task_complete', (data) => {
        showThinking(false);
        finalizeStreamingMessage();
        handleTaskComplete(data);
        updateTokenUsage(data.token_usage);
    });

    socket.on('tool_result', (data) => {
        toolCount++;
        updateMeta();
        appendLiveOutput(data);
    });

    socket.on('error', (data) => {
        showThinking(false);
        addSystemMessage(`❌ Error: ${data.message}`);
    });

    socket.on('autonomous_changed', (data) => {
        autonomousEnabled = data.enabled;
        updateAutonomousToggleUI();
    });

    // ── Workflow events ──
    socket.on('workflow_start', (data) => {
        addSystemMessage(`🚀 Workflow started: ${data.workflow?.name || 'unknown'} (task: ${data.task_id})`);
    });

    socket.on('workflow_complete', (data) => {
        const status = (data.status || 'unknown').toUpperCase();
        addSystemMessage(`🏁 Workflow complete: ${status} — ${data.completed_steps}/${data.total_steps} steps`);
        if (data.chain_values && Object.keys(data.chain_values).length) {
            const chainText = Object.entries(data.chain_values)
                .map(([k, v]) => `• ${k} = ${String(v).slice(0, 60)}`).join('\n');
            addSystemMessage(`🔗 Exploit chain values:\n${chainText}`);
        }
        if (data.status === 'complete') {
            addSystemMessage(`✅ Full workflow completed — output at: ${data.root}`);
        }
    });

    socket.on('workflow_result', (data) => {
        handleWorkflowResult(data);
    });

    socket.on('workflow_multi_result', (data) => {
        handleMultiWorkflowResult(data);
    });

    socket.on('workflow_generated', (data) => {
        handleWorkflowGenerated(data);
    });
}

// ═══════════════════════════════════════════════════════════════
// Streaming Message Support
// ═══════════════════════════════════════════════════════════════
function addAssistantMessageStream() {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message assistant streaming';
    msg.innerHTML = '<div class="msg-content" id="stream-content"></div>';
    container.appendChild(msg);
    scrollToBottom();
    return msg;
}

function appendToStreamingMessage(chunk) {
    const el = document.getElementById('stream-content');
    if (el) {
        el.innerHTML += formatMarkdown(chunk);
        scrollToBottom();
    }
}

function finalizeStreamingMessage() {
    if (streamingMessage) {
        streamingMessage.classList.remove('streaming');
        streamingMessage = null;
    }
}

// ═══════════════════════════════════════════════════════════════
// Status & Indicators
// ═══════════════════════════════════════════════════════════════
function updateStatusIndicators(data) {
    const llmDot = document.getElementById('llm-status');
    const llmLabel = document.getElementById('llm-label');
    const toolsDot = document.getElementById('tools-status');
    const toolsLabel = document.getElementById('tools-label');

    if (data.llm_connected) {
        llmDot.className = 'status-dot green';
        llmLabel.textContent = 'LLM: Connected';
    } else {
        llmDot.className = 'status-dot';
        llmLabel.textContent = 'LLM: Disconnected';
    }

    toolsLabel.textContent = `Tools: ${data.tools_available}/${data.tools_total}`;
}

function updateLLMStatus(connected) {
    const dot = document.getElementById('llm-status');
    const label = document.getElementById('llm-label');
    dot.className = connected ? 'status-dot green' : 'status-dot';
    label.textContent = connected ? 'LLM: Connected' : 'LLM: Disconnected';
}

function updateTokenUsage(usage) {
    if (!usage) return;
    const bar = document.getElementById('token-bar-fill');
    const label = document.getElementById('token-bar-label');
    if (bar && usage.total_tokens) {
        const max = 65536;
        const pct = Math.min(100, (usage.total_tokens / max) * 100);
        bar.style.width = pct + '%';
        bar.className = pct > 80 ? 'token-bar-fill warn' : 'token-bar-fill';
        label.textContent = `${(usage.total_tokens/1000).toFixed(1)}k / 65k tokens`;
    }
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        updateStatusIndicators(data);
        updateTokenUsage(data.token_usage);
        if (data.session) {
            sessionId = data.session;
            document.getElementById('session-id').textContent = sessionId;
            document.getElementById('meta-session').textContent = sessionId;
        }
    } catch (e) {
        console.error('Status load failed:', e);
    }
}

function updateMeta() {
    document.getElementById('meta-steps').textContent = stepCount;
    document.getElementById('meta-tools-run').textContent = toolCount;
}

// ═══════════════════════════════════════════════════════════════
// Autonomous Mode
// ═══════════════════════════════════════════════════════════════
function initAutonomousToggle() {
    const toggle = document.getElementById('autonomous-toggle');
    if (toggle) {
        toggle.addEventListener('change', () => {
            autonomousEnabled = toggle.checked;
            socket.emit('set_autonomous', { enabled: autonomousEnabled });
        });
    }
}

function updateAutonomousToggleUI() {
    const toggle = document.getElementById('autonomous-toggle');
    if (toggle) {
        toggle.checked = autonomousEnabled;
    }
}

// ═══════════════════════════════════════════════════════════════
// Chat
// ═══════════════════════════════════════════════════════════════
function initInput() {
    const input = document.getElementById('chat-input');
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}

function sendMessage() {
    const input = document.getElementById('chat-input');
    const prompt = input.value.trim();
    if (!prompt) return;

    addUserMessage(prompt);
    input.value = '';
    showThinking(true);
    stepCount++;
    streamingMessage = null;

    socket.emit('send_task', { prompt, session_id: sessionId });
}

function sendQuickPrompt(prompt) {
    document.getElementById('chat-input').value = prompt;
    sendMessage();
}

function addUserMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message user';
    msg.innerHTML = `<div class="msg-content">${escapeHtml(text)}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addAssistantMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message assistant';
    msg.innerHTML = `<div class="msg-content">${formatMarkdown(text)}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addSystemMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message system';
    msg.innerHTML = `<div class="msg-content">${text}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addToolMessage(tool, args, status) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message tool';
    const statusColor = status === 'running' ? 'var(--accent-yellow)' : 'var(--accent-green)';
    msg.innerHTML = `
        <div class="tool-header">
            <span class="tool-badge">${escapeHtml(tool)}</span>
            <span class="tool-status" style="color:${statusColor}">${status === 'running' ? '⏳ Running...' : '✓ Complete'}</span>
        </div>
        <pre>${escapeHtml(JSON.stringify(args, null, 2))}</pre>
    `;
    msg.id = `tool-msg-${tool}-${Date.now()}`;
    container.appendChild(msg);
    scrollToBottom();
    return msg.id;
}

function updateToolResult(data) {
    const messages = document.querySelectorAll('.message.tool');
    const last = messages[messages.length - 1];
    if (last) {
        const statusEl = last.querySelector('.tool-status');
        if (statusEl) {
            const success = data.result?.status === 'success' || data.result?.exit_code === 0;
            statusEl.textContent = success ? '✓ Complete' : `✗ Failed (${data.result?.exit_code ?? '?'})`;
            statusEl.style.color = success ? 'var(--accent-green)' : 'var(--accent-red)';
        }
    }
}

function handleTaskComplete(data) {
    const steps = data.steps || [];
    for (const step of steps) {
        if (step.llm_response && !streamingMessage) {
            addAssistantMessage(step.llm_response);
        }
        if (step.results) {
            for (const r of step.results) {
                if (r.status === 'blocked') {
                    addSystemMessage(`⚠️ Tool ${r.tool} blocked: ${r.reason}`);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Plan & Report panels
// ═══════════════════════════════════════════════════════════════
function showPlan(plan) {
    const el = document.getElementById('plan-content');
    if (!el) return;
    if (!plan || plan.length === 0) {
        el.innerHTML = '<p class="muted">No plan generated.</p>';
        return;
    }
    el.innerHTML = plan.map(s => `
        <div class="plan-step">
            <span class="plan-step-num">${s.step || '?'}</span>
            <div>
                <strong>${escapeHtml(s.tool || '?')}</strong>
                <div class="plan-step-desc">${escapeHtml(s.description || '')}</div>
                ${s.target ? `<code>${escapeHtml(s.target)}</code>` : ''}
            </div>
        </div>
    `).join('');
}

function showReport(report) {
    const el = document.getElementById('report-content');
    if (!el) return;
    if (!report) {
        el.innerHTML = '<p class="muted">No report generated.</p>';
        return;
    }
    el.innerHTML = formatMarkdown(report);
    // Switch to report tab
    showResultsTab('report');
}

function scrollToBottom() {
    const container = document.getElementById('chat-messages');
    container.scrollTop = container.scrollHeight;
}

function showThinking(show) {
    const indicator = document.getElementById('thinking-indicator');
    const sendBtn = document.getElementById('send-btn');
    if (show) {
        indicator.classList.remove('hidden');
        sendBtn.disabled = true;
    } else {
        indicator.classList.add('hidden');
        sendBtn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════
// Tools Panel
// ═══════════════════════════════════════════════════════════════
async function loadTools() {
    try {
        const res = await fetch('/api/tools');
        const data = await res.json();
        renderTools(data);
    } catch (e) {
        console.error('Tools load failed:', e);
    }
}

function renderTools(toolsByCategory) {
    const list = document.getElementById('tool-list');
    list.innerHTML = '';

    for (const [category, tools] of Object.entries(toolsByCategory)) {
        for (const tool of tools) {
            if (currentCategory !== 'all' && tool.category !== currentCategory) continue;
            const item = document.createElement('div');
            item.className = `tool-item ${tool.installed ? 'installed' : 'missing'}`;
            item.innerHTML = `
                <div>
                    <div class="tool-name">${escapeHtml(tool.name)}</div>
                    <div class="tool-category">${escapeHtml(tool.category)} ${tool.installed ? '✓' : '✗'}</div>
                </div>
            `;
            item.onclick = () => showToolDialog(tool);
            list.appendChild(item);
        }
    }
}

async function loadQuickCommands() {
    try {
        const res = await fetch('/api/tools/quick-commands');
        const commands = await res.json();
        const list = document.getElementById('quick-commands-list');
        list.innerHTML = '';
        for (const cmd of commands.slice(0, 12)) {
            const btn = document.createElement('button');
            btn.className = 'quick-cmd';
            btn.innerHTML = `<span class="cmd-name">${escapeHtml(cmd.name)}</span><span class="cmd-desc">${escapeHtml(cmd.description)}</span>`;
            btn.onclick = () => {
                if (cmd.note) {
                    addSystemMessage(`ℹ️ ${escapeHtml(cmd.note)}`);
                } else {
                    const argsJson = JSON.stringify(cmd.args_template).replace(/TARGET/g, '192.168.1.1');
                    sendQuickPrompt(`Execute tool "${escapeHtml(cmd.tool)}" with args: ${argsJson}`);
                }
            };
            list.appendChild(btn);
        }
    } catch (e) {
        console.error('Quick commands load failed:', e);
    }
}

async function loadAttackChains() {
    try {
        const res = await fetch('/api/tools/attack-chains');
        const chains = await res.json();
        const list = document.getElementById('attack-chains-list');
        list.innerHTML = '';
        for (const chain of chains) {
            const el = document.createElement('div');
            el.className = 'attack-chain';
            el.innerHTML = `
                <div class="chain-name">${escapeHtml(chain.name)}</div>
                <div class="chain-desc">${escapeHtml(chain.description)}</div>
            `;
            el.onclick = () => {
                sendQuickPrompt(`Run attack chain "${escapeHtml(chain.name)}": ${escapeHtml(chain.description)}`);
            };
            list.appendChild(el);
        }
    } catch (e) {
        console.error('Attack chains load failed:', e);
    }
}

function showToolDialog(tool) {
    const prompt = `Execute tool "${escapeHtml(tool.name)}" against target. Describe the target and parameters.`;
    document.getElementById('chat-input').value = prompt;
    document.getElementById('chat-input').focus();
}

function initTabs() {
    document.querySelectorAll('.tool-tabs .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tool-tabs .tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentCategory = tab.dataset.category;
            loadTools();
        });
    });
}

// ═══════════════════════════════════════════════════════════════
// Workflows (v3.0)
// ═══════════════════════════════════════════════════════════════
async function loadWorkflows() {
    try {
        const res = await fetch('/api/workflows');
        const workflows = await res.json();
        const list = document.getElementById('workflows-list');
        if (workflows.length === 0) {
            list.innerHTML = '<p class="muted">No workflow templates found.</p>';
            return;
        }
        list.innerHTML = workflows.map(w => `
            <div class="attack-chain">
                <div class="chain-name">${escapeHtml(w.name)}</div>
                <div class="chain-desc">${escapeHtml(w.category)} · ${w.steps_count} steps ${w.cutting_edge ? '· 🔥 Cutting-edge' : ''}</div>
            </div>
        `).join('');

        // Populate modal select
        const select = document.getElementById('wf-select');
        if (select) {
            select.innerHTML = '<option value="">Select a workflow...</option>' +
                workflows.map(w => `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)}</option>`).join('');
        }
    } catch (e) {
        console.error('Workflows load failed:', e);
    }
}

function openWorkflowModal() {
    document.getElementById('workflow-modal').classList.remove('hidden');
    document.getElementById('wf-select').addEventListener('change', onWorkflowSelect);
}

function closeWorkflowModal() {
    document.getElementById('workflow-modal').classList.add('hidden');
}

async function onWorkflowSelect() {
    const name = document.getElementById('wf-select').value;
    const runBtn = document.getElementById('wf-run-btn');
    if (!name) {
        document.getElementById('wf-details').classList.add('hidden');
        runBtn.disabled = true;
        return;
    }
    // Fetch the summary to show details + build variable inputs
    const res = await fetch('/api/workflows');
    const workflows = await res.json();
    const wf = workflows.find(w => w.name === name);
    if (!wf) return;

    const details = document.getElementById('wf-details');
    details.classList.remove('hidden');
    details.innerHTML = `
        <div class="wf-desc">${escapeHtml(wf.description)}</div>
        <div class="wf-steps">Steps: ${wf.steps.map(s => escapeHtml(s)).join(' → ')}</div>
        ${wf.cutting_edge ? '<div class="wf-badge">🔥 Cutting-edge attack</div>' : ''}
    `;

    // Build variable inputs
    const varsBox = document.getElementById('wf-vars');
    if (wf.variables && wf.variables.length) {
        varsBox.innerHTML = wf.variables.map(v => `
            <div class="wf-var-row">
                <label class="modal-label" for="wf-var-${escapeHtml(v)}">${escapeHtml(v)}</label>
                <input class="modal-input" id="wf-var-${escapeHtml(v)}" placeholder="${escapeHtml(v)}" data-var="${escapeHtml(v)}">
            </div>
        `).join('');
    } else {
        varsBox.innerHTML = '<input class="modal-input" id="wf-var-target" placeholder="target" data-var="target">';
    }
    runBtn.disabled = false;
}

async function runWorkflowFromModal() {
    const name = document.getElementById('wf-select').value;
    if (!name) return;

    // Collect variables
    const variables = {};
    document.querySelectorAll('#wf-vars input[data-var]').forEach(inp => {
        if (inp.value.trim()) variables[inp.dataset.var] = inp.value.trim();
    });
    // Add target from chat if not provided
    if (!variables.target) variables.target = '192.168.1.1';

    // Multi-target mode: comma-separated targets → concurrent execution
    const targetsField = document.getElementById('wf-targets');
    const targets = (targetsField?.value || '').split(',').map(t => t.trim()).filter(Boolean);

    closeWorkflowModal();
    if (targets.length > 1) {
        addSystemMessage(`🚀 Launching multi-target workflow: ${escapeHtml(name)} against ${targets.length} targets (concurrent)`);
        socket.emit('run_multi_workflow', { workflow: name, targets, variables });
    } else {
        if (targets.length === 1) variables.target = targets[0];
        addSystemMessage(`🚀 Launching workflow: ${escapeHtml(name)}`);
        socket.emit('run_workflow', { workflow: name, variables });
    }
}

async function generateWorkflowFromModal() {
    const objective = document.getElementById('wf-objective').value.trim();
    if (!objective) return;
    const btn = document.getElementById('wf-gen-btn');
    const resultBox = document.getElementById('wf-gen-result');
    btn.disabled = true;
    btn.textContent = '🧠 Generating...';
    resultBox.classList.remove('hidden');
    resultBox.innerHTML = '<p class="muted">Asking the local LLM to design a workflow...</p>';
    try {
        const res = await fetch('/api/workflows/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ objective }),
        });
        const data = await res.json();
        if (data.error) {
            resultBox.innerHTML = `<p class="muted">❌ ${escapeHtml(data.error)}</p>`;
            if (data.validation_errors) {
                resultBox.innerHTML += `<div class="wf-steps">${data.validation_errors.map(e => escapeHtml(e)).join('<br>')}</div>`;
            }
        } else {
            resultBox.innerHTML = `
                <div class="wf-desc"><b>${escapeHtml(data.name)}</b> — ${escapeHtml(data.description || '')}</div>
                <div class="wf-steps">Steps: ${(data.steps || []).map(s => escapeHtml(s)).join(' → ')}</div>
                <div class="wf-badge">✨ Generated by LLM · saved as template</div>
            `;
            // Refresh workflow list + select the new template
            await loadWorkflows();
            const select = document.getElementById('wf-select');
            if (select) select.value = data.name;
            onWorkflowSelect();
            document.getElementById('wf-run-btn').disabled = false;
        }
    } catch (e) {
        resultBox.innerHTML = `<p class="muted">❌ Generation failed: ${escapeHtml(e.message)}</p>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '✨ Generate with LLM';
    }
}

function handleWorkflowGenerated(data) {
    // WebSocket path: the payload is a GENERATION summary (name, steps =
    // list of names), NOT a workflow result — handle it as such.
    if (data.error) {
        addSystemMessage(`❌ Generation failed: ${escapeHtml(data.error)}`);
        if (data.validation_errors) {
            addSystemMessage(data.validation_errors.map(e => `⚠️ ${escapeHtml(e)}`).join('<br>'));
        }
        return;
    }
    addSystemMessage(`✨ Generated workflow: ${escapeHtml(data.name)} — ${(data.steps || []).length} steps`);
    loadWorkflows();
}

function handleWorkflowResult(data) {
    if (data.error) {
        addSystemMessage(`❌ Workflow error: ${escapeHtml(data.error)}`);
        return;
    }
    const status = (data.status || 'unknown').toUpperCase();
    addSystemMessage(`🏁 Workflow finished: ${status} (${data.completed_steps || 0}/${data.total_steps || 0} steps)`);
    if (data.steps) {
        for (const s of data.steps) {
            const icon = s.status === 'success' ? '✅' : (s.gate_failed ? '⛔' : '⚠️');
            addSystemMessage(`${icon} ${escapeHtml(s.step)} — ${s.status} (attempts=${s.attempts})`);
        }
    }
    // Phase 7: correlate findings into attack paths + remediation
    if (data.findings && data.findings.length) {
        renderFindings(data.findings);
        correlateFindings(data.findings);
    }
}

function handleMultiWorkflowResult(data) {
    if (data.error) {
        addSystemMessage(`❌ Multi-target error: ${escapeHtml(data.error)}`);
        return;
    }
    const status = (data.status || 'unknown').toUpperCase();
    addSystemMessage(`🏁 Multi-target workflow finished: ${status} — ${(data.targets || []).length} targets`);
    if (data.per_target) {
        for (const [target, r] of Object.entries(data.per_target)) {
            const icon = (r.status === 'complete' || r.status === 'partial') ? '✅' : '❌';
            addSystemMessage(`${icon} ${escapeHtml(target)} — ${r.status} (${r.steps_count}/${r.total_steps} steps)${r.error ? ' — ' + escapeHtml(r.error) : ''}`);
        }
    }
    if (data.pooled_findings && data.pooled_findings.length) {
        renderFindings(data.pooled_findings);
        correlateFindings(data.pooled_findings);
    }
}

async function correlateFindings(findings) {
    try {
        const res = await fetch('/api/correlate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings }),
        });
        const data = await res.json();
        if (data.paths && data.paths.length) {
            renderAttackPaths(data.paths);
        }
    } catch (e) {
        console.error('Correlation failed:', e);
    }
}

function renderFindings(findings) {
    const el = document.getElementById('findings-list');
    if (!el) return;
    el.innerHTML = findings.slice(0, 50).map(f => `
        <div class="plan-step">
            <span class="plan-step-num sev-${escapeHtml(f.severity || 'info')}">${escapeHtml((f.severity || 'info').slice(0, 1).toUpperCase())}</span>
            <div>
                <strong>${escapeHtml(f.title || '')}</strong>
                ${f.target ? `<span class="muted"> · ${escapeHtml(f.target)}</span>` : ''}
                <div class="plan-step-desc">${escapeHtml(f.evidence || '')}</div>
                <code>${escapeHtml(f.source_tool || '')}</code>
            </div>
        </div>
    `).join('');
}

function renderAttackPaths(paths) {
    const el = document.getElementById('findings-list');
    if (!el) return;
    const pathHtml = paths.map(p => `
        <div class="attack-path">
            <div class="attack-path-head">
                <span class="plan-step-num sev-${escapeHtml(p.severity || 'medium')}">${escapeHtml((p.severity || 'medium').toUpperCase())}</span>
                <strong>${escapeHtml(p.title)}</strong>
                <span class="muted">score ${p.score || '?'}</span>
            </div>
            <div class="plan-step-desc">${(p.remediation || []).map(r => `• ${escapeHtml(r)}`).join('<br>')}</div>
        </div>
    `).join('');
    el.innerHTML = `<div class="path-header">🔗 Correlated Attack Paths</div>${pathHtml}${el.innerHTML}`;
}

// ═══════════════════════════════════════════════════════════════
// Workflow Chain Graph (Phase 4)
// ═══════════════════════════════════════════════════════════════
async function populateGraphSelect() {
    try {
        const res = await fetch('/api/workflows');
        const workflows = await res.json();
        const sel = document.getElementById('graph-wf-select');
        if (!sel) return;
        sel.innerHTML = '<option value="">Select workflow to visualize...</option>' +
            workflows.map(w => `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)}</option>`).join('');
    } catch (e) {
        console.error('Graph select load failed:', e);
    }
}

async function renderWorkflowGraph() {
    const sel = document.getElementById('graph-wf-select');
    const name = sel ? sel.value : '';
    const content = document.getElementById('graph-content');
    if (!name) {
        content.innerHTML = '<p class="muted">Pick a workflow to see its attack chain graph.</p>';
        return;
    }
    content.innerHTML = '<p class="muted">Rendering chain graph...</p>';
    try {
        const res = await fetch(`/api/workflows/graph/${encodeURIComponent(name)}`);
        const graph = await res.json();
        if (graph.error) {
            content.innerHTML = `<p class="muted">${escapeHtml(graph.error)}</p>`;
            return;
        }
        content.innerHTML = drawChainGraph(graph);
    } catch (e) {
        content.innerHTML = `<p class="muted">Graph load failed: ${escapeHtml(e.message)}</p>`;
    }
}

function drawChainGraph(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (!nodes.length) return '<p class="muted">No steps in this workflow.</p>';

    // Build id → index map
    const idIdx = {};
    nodes.forEach((n, i) => idIdx[n.id] = i);

    // Column layout: sequential flow left→right; chain edges may pull right
    const COLS = nodes.length;
    const NODE_W = 180, NODE_H = 64, GX = 60, GY = 100;
    const W = COLS * (NODE_W + GX) + GX;
    const H = 2 * (NODE_H + GY) + 60;

    const colors = {
        pending: '#5b6b7a', success: '#22c55e', failed: '#ef4444',
        blocked: '#ef4444', running: '#f59e0b', not_started: '#5b6b7a',
    };

    // Position: try to place nodes with chain deps on the same row
    const pos = {};
    const rowOf = {};
    nodes.forEach((n, i) => {
        rowOf[n.id] = 0;
    });
    // Chain deps pull target up to dep's row
    edges.forEach(e => {
        if (e.kind === 'chain' && idIdx[e.to] !== undefined && idIdx[e.from] !== undefined) {
            rowOf[e.to] = Math.max(rowOf[e.to], rowOf[e.from]);
        }
    });
    nodes.forEach((n, i) => {
        pos[n.id] = { x: GX + i * (NODE_W + GX), y: 40 + rowOf[n.id] * (NODE_H + GY) };
    });

    let svg = `<svg viewBox="0 0 ${W} ${Math.max(H, 220)}" class="chain-svg" xmlns="http://www.w3.org/2000/svg">`;
    svg += `<defs>
        <marker id="arrow-seq" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#7c8a99"/></marker>
        <marker id="arrow-chain" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#22c55e"/></marker>
    </defs>`;

    // Draw edges first (behind nodes)
    for (const e of edges) {
        const a = pos[e.from], b = pos[e.to];
        if (!a || !b) continue;
        const isChain = e.kind === 'chain';
        const x1 = a.x + NODE_W / 2, y1 = a.y + NODE_H / 2;
        const x2 = b.x + NODE_W / 2, y2 = b.y + NODE_H / 2;
        const stroke = isChain ? '#22c55e' : '#7c8a99';
        const dash = isChain ? '6,4' : 'none';
        const marker = isChain ? 'url(#arrow-chain)' : 'url(#arrow-seq)';
        const curve = isChain
            ? `M ${x1} ${y1} C ${x1 + 60} ${y1}, ${x2 - 60} ${y2}, ${x2} ${y2}`
            : `M ${x1} ${y1} L ${x2} ${y2}`;
        svg += `<path d="${curve}" fill="none" stroke="${stroke}" stroke-width="${isChain ? 2 : 1.5}" stroke-dasharray="${dash}" marker-end="${marker}">
            <title>${isChain ? 'Exploit chain: extracted data flows' : 'Sequential step'} ${escapeXml(e.from)} → ${escapeXml(e.to)}</title></path>`;
    }

    // Draw nodes
    for (const n of nodes) {
        const p = pos[n.id];
        const fill = colors[n.status] || colors.pending;
        const gate = n.gate ? '⛔' : '';
        svg += `<g>
            <rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="10"
                  fill="#0d1620" stroke="${fill}" stroke-width="2"/>
            <text x="${p.x + 10}" y="${p.y + 22}" fill="${fill}" font-size="13" font-weight="bold">${n.index}. ${gate} ${escapeXml(n.tool)}</text>
            <text x="${p.x + 10}" y="${p.y + 42}" fill="#94a3b8" font-size="11">${escapeXml(n.id)}</text>
            <text x="${p.x + 10}" y="${p.y + 57}" fill="${fill}" font-size="10">${escapeXml(String(n.status).toUpperCase())}</text>
            <title>${escapeXml(n.description || '')}</title>
        </g>`;
    }

    svg += '</svg>';

    // Legend + summary
    const fs = graph.findings_summary || {};
    const summary = Object.keys(fs).filter(k => fs[k] > 0)
        .map(k => `<span class="legend-item sev-${k}">${k}: ${fs[k]}</span>`).join('');
    return `<div class="graph-wrap">
        <div class="graph-status">Status: <b>${escapeHtml(graph.status || 'not_started')}</b> · Findings: ${summary || 'none yet'}</div>
        ${svg}
        <div class="graph-legend">
            <span class="legend-item"><span class="dot seq"></span> Sequential</span>
            <span class="legend-item"><span class="dot chain"></span> Exploit chain</span>
            <span class="legend-item"><span class="dot pend"></span> Pending</span>
            <span class="legend-item"><span class="dot succ"></span> Success</span>
            <span class="legend-item"><span class="dot fail"></span> Failed</span>
            <span class="legend-item"><span class="dot gate"></span> ⛔ Gate step</span>
        </div>
    </div>`;
}

function escapeXml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// ═══════════════════════════════════════════════════════════════
// Results Area
// ═══════════════════════════════════════════════════════════════
function showResultsTab(tab) {
    document.querySelectorAll('.results-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.results-tabs .tab').forEach(t => t.classList.remove('active'));
    const target = document.getElementById(`results-${tab}`);
    if (target) target.classList.remove('hidden');
    // Activate clicked tab
    const tabs = document.querySelectorAll('.results-tabs .tab');
    for (const t of tabs) {
        if (t.textContent.toLowerCase().includes(tab)) t.classList.add('active');
    }
}

function appendLiveOutput(data) {
    const el = document.getElementById('live-output');
    const timestamp = new Date().toLocaleTimeString();
    const result = data.result || data;
    const output = result.summary || result.stdout || result.stderr || JSON.stringify(result, null, 2);
    el.textContent = `[${timestamp}] ${result.tool || data.tool || 'tool'} (exit: ${result.exit_code ?? '?'}):\n${output}\n\n${el.textContent}`;
}

function addCommandToLog(data) {
    const result = data.result || data;
    const entry = {
        time: new Date().toLocaleTimeString(),
        tool: result.tool,
        args: result.args,
        exit_code: result.exit_code,
        duration: result.duration_seconds,
    };
    commandLog.unshift(entry);

    const log = document.getElementById('command-log');
    log.innerHTML = commandLog.map(c => `
        <div class="safety-item">
            <span class="label">${c.time} ${escapeHtml(c.tool)}</span>
            <span class="value">${c.exit_code === 0 ? '✓' : '✗'} ${c.duration || ''}s</span>
        </div>
    `).join('');
}

// ═══════════════════════════════════════════════════════════════
// Sessions & Safety
// ═══════════════════════════════════════════════════════════════
async function loadSessions() {
    try {
        const res = await fetch('/api/sessions');
        const sessions = await res.json();
        const el = document.getElementById('sessions-list-content');
        if (sessions.length === 0) {
            el.innerHTML = '<p class="muted">No past sessions.</p>';
            return;
        }
        el.innerHTML = sessions.map(s => `
            <div class="safety-item">
                <span class="label">${escapeHtml(s.name)}</span>
                <span class="value">${s.tool_calls} tools</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Sessions load failed:', e);
    }
}

async function loadSafety() {
    try {
        const res = await fetch('/api/safety');
        const data = await res.json();
        const el = document.getElementById('safety-info-content');
        el.innerHTML = `
            <div class="safety-item">
                <span class="label">Allowed Targets</span>
                <span class="value">${data.allowed_targets?.length || 0} ranges</span>
            </div>
            <div class="safety-item">
                <span class="label">Blocked Targets</span>
                <span class="value">${data.blocked_targets?.length || 0} hosts</span>
            </div>
            <div class="safety-item">
                <span class="label">Confirm Required</span>
                <span class="value">${data.require_confirmation?.length || 0} tools</span>
            </div>
        `;
    } catch (e) {
        console.error('Safety load failed:', e);
    }
}

// ═══════════════════════════════════════════════════════════════
// Panel Toggle
// ═══════════════════════════════════════════════════════════════
function togglePanel(id) {
    document.getElementById(id).classList.toggle('collapsed');
}

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

function formatMarkdown(text) {
    return (text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/```([\s\S]*?)```/g, '<pre>$1</pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
}