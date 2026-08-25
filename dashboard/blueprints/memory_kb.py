"""RedTeam Harness - Dashboard blueprint: vector memory + offline KB.
RAG memory stats/targets/query/export/import/reset and the offline
knowledge base (CVE / ATT&CK / exploit signatures / remediation).
"""
import os
import io
import json
import zipfile
from flask import request, jsonify, Response


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

    # ═══════════════════════════════════════════════════
    # Vector Memory / RAG Routes
    # ═══════════════════════════════════════════════════
    @app.route("/api/memory/stats")
    def api_memory_stats():
        """Get vector memory statistics."""
        return jsonify(orchestrator.memory.get_stats())

    @app.route("/api/memory/targets")
    def api_memory_targets():
        """List all targets stored in vector memory."""
        return jsonify(orchestrator.memory.list_targets())

    @app.route("/api/memory/query", methods=["POST"])
    def api_memory_query():
        """Search vector memory by text similarity."""
        data = request.get_json()
        query_text = data.get("query", "")
        if not query_text:
            return jsonify({"error": "No query provided"}), 400
        top_k = data.get("top_k", 10)
        target_filter = data.get("target", "")
        results = orchestrator.memory.query(query_text, top_k=top_k,
                                           target_filter=target_filter)
        return jsonify({"results": results, "count": len(results)})

    @app.route("/api/memory/target/<target>")
    def api_memory_target_findings(target):
        """Get all past findings for a specific target."""
        results = orchestrator.memory.query_by_target(target)
        context = orchestrator.memory.get_context_block(target)
        return jsonify({"target": target, "findings": results,
                        "count": len(results), "context_block": context})

    @app.route("/api/memory/export")
    def api_memory_export():
        """Export vector memory as a portable .zip bundle."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            mem_dir = orchestrator.memory._memory_dir
            for fname in ['index.json', 'vocab.json']:
                fpath = os.path.join(mem_dir, fname)
                if os.path.exists(fpath):
                    zf.write(fpath, fname)
            vectors_path = os.path.join(mem_dir, 'vectors.npy')
            if os.path.exists(vectors_path):
                zf.write(vectors_path, 'vectors.npy')
            zf.writestr('stats.json', json.dumps(orchestrator.memory.get_stats()))
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype='application/zip',
            headers={'Content-Disposition':
                     'attachment; filename=redteam_memory_export.zip'})

    @app.route("/api/memory/import", methods=["POST"])
    def api_memory_import():
        """Import vector memory from an uploaded .zip bundle."""
        f = request.files.get('file')
        if not f:
            return jsonify({"error": "No file uploaded"}), 400
        try:
            data = f.read()
            zf = zipfile.ZipFile(io.BytesIO(data))
            mem_dir = orchestrator.memory._memory_dir
            imported = 0
            for name in zf.namelist():
                if name in ('index.json', 'vocab.json', 'vectors.npy'):
                    zf.extract(name, mem_dir)
                    imported += 1
            if imported > 0:
                orchestrator.memory._load()
                return jsonify({"imported": imported,
                                "stats": orchestrator.memory.get_stats()})
            return jsonify({"error": "No valid memory files in archive"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/memory/reset", methods=["POST"])
    def api_memory_reset():
        """Clear all stored vector memory."""
        orchestrator.memory.reset()
        return jsonify({"reset": True})


    # ═══════════════════════════════════════════════════
    # Offline Knowledge Base (v5.6) — CVE / ATT&CK / exploits / remediation
    # ═══════════════════════════════════════════════════
    @app.route("/api/kb/stats")
    def api_kb_stats():
        """Get offline knowledge base statistics."""
        return jsonify(orchestrator.kb.get_stats())

    @app.route("/api/kb/search", methods=["POST"])
    def api_kb_search():
        """Search the offline KB by text (CVEs, techniques, signatures, playbooks)."""
        data = request.get_json() or {}
        query = (data.get("query") or "").strip()
        if not query:
            return jsonify({"error": "No query provided"}), 400
        top_k = min(int(data.get("top_k", 8)), 50)
        results = orchestrator.kb.search(query, top_k=top_k)
        return jsonify({"results": results, "count": len(results), "query": query})

    @app.route("/api/kb/cve/<cve_id>")
    def api_kb_cve(cve_id):
        """Look up a single CVE in the offline database."""
        entry = orchestrator.kb.lookup_cve(cve_id.upper())
        if not entry:
            return jsonify({"error": f"CVE {cve_id} not in offline database"}), 404
        entry["remediation"] = orchestrator.kb.remediation_for(cve_id.upper())
        return jsonify(entry)

    @app.route("/api/kb/technique/<tech_id>")
    def api_kb_technique(tech_id):
        """Look up a single MITRE ATT&CK technique."""
        entry = orchestrator.kb.lookup_technique(tech_id.upper())
        if not entry:
            return jsonify({"error": f"Technique {tech_id} not in offline database"}), 404
        return jsonify(entry)

    @app.route("/api/kb/ground", methods=["POST"])
    def api_kb_ground():
        """Ground a finding/scan text against the KB — returns matched
        CVEs, techniques, signatures and remediation for the given text."""
        data = request.get_json() or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"error": "No text provided"}), 400
        sigs = orchestrator.kb.signature_match(text)
        top = orchestrator.kb.search(text, top_k=4)
        return jsonify({"signatures": sigs,
                        "related": top,
                        "text_preview": text[:400]})
