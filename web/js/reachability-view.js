/* Reachability path visualization for CloudMapper.
 *
 * Consumes the output of:
 *   cloudmapper.py reachability --graph web/data.json \
 *       --web-overlay web/reachability.json
 * or the multi-account demo bundle web/reachability-demo.json.
 */
(function () {
  "use strict";

  var cy = null;
  var bundle = null;
  var current = null; // {name, graph, report}
  var edgeEvidence = {};

  var statusEl = document.getElementById("status");
  var summaryEl = document.getElementById("summary");
  var pathsEl = document.getElementById("paths");
  var detailsEl = document.getElementById("details");
  var selectEl = document.getElementById("accountSelect");

  function setStatus(text) { statusEl.textContent = text; }

  function shortId(id) {
    if (id == null) return "";
    id = String(id);
    if (/^\d{1,3}(\.\d{1,3}){3}\/\d+$/.test(id) || id.indexOf("::/") !== -1) return id;
    var marker = id.indexOf(":instance/");
    if (marker !== -1) {
      var rest = id.substring(marker + ":instance/".length);
      return rest.split("/")[0];
    }
    if (id.lastIndexOf("/") !== -1) id = id.substring(id.lastIndexOf("/") + 1);
    else if (id.lastIndexOf(":") !== -1) id = id.substring(id.lastIndexOf(":") + 1);
    id = id.replace(/\.?subnet-[0-9a-f]+$/, "");
    return id;
  }

  function edgeKey(source, target) { return source + "=>" + target; }

  function isBundle(json) {
    return json && Object.prototype.hasOwnProperty.call(json, "accounts") &&
      json.accounts && json.accounts.length && json.accounts[0].graph;
  }

  function fetchJson(path) {
    return fetch(path, { cache: "no-store" }).then(function (resp) {
      if (!resp.ok) throw new Error(path + " -> HTTP " + resp.status);
      return resp.json();
    });
  }

  function init() {
    document.getElementById("showAll").addEventListener("click", showAllPaths);
    selectEl.addEventListener("change", function () {
      var idx = parseInt(selectEl.value, 10);
      if (bundle && bundle.accounts[idx]) renderAccount(bundle.accounts[idx]);
    });
    document.getElementById("graphFile").addEventListener("change", onGraphFile);
    document.getElementById("reportFile").addEventListener("change", onReportFile);

    fetchJson("reachability-demo.json")
      .then(function (json) {
        if (!isBundle(json)) throw new Error("not a bundle");
        loadBundle(json);
      })
      .catch(function () {
        return Promise.all([
          fetchJson("data.json").catch(function () { return null; }),
          fetchJson("reachability.json").catch(function () { return null; })
        ]).then(function (results) {
          var graph = results[0], report = results[1];
          if (report && isBundle(report)) { loadBundle(report); return; }
          if (graph && report) {
            renderAccount({ name: report.account || "account", graph: graph, report: report });
            setStatus("Loaded data.json + reachability.json");
          } else {
            setStatus("No reachability data found. Generate web/reachability.json or use the file pickers.");
          }
        });
      });
  }

  function loadBundle(json) {
    bundle = json;
    selectEl.innerHTML = "";
    json.accounts.forEach(function (account, idx) {
      var option = document.createElement("option");
      option.value = String(idx);
      option.textContent = account.name + (account.title ? " - " + account.title : "");
      selectEl.appendChild(option);
    });
    renderAccount(json.accounts[0]);
    setStatus("Loaded " + json.accounts.length + " account bundle");
  }

  var pendingGraph = null;
  function onGraphFile(event) {
    readJsonFile(event.target.files[0], function (json) {
      pendingGraph = json;
      if (!current || !current.report) renderAccount({ name: "custom graph", graph: json, report: emptyReport() });
      else renderAccount({ name: current.name, graph: json, report: current.report });
    });
  }

  function onReportFile(event) {
    readJsonFile(event.target.files[0], function (json) {
      if (isBundle(json)) { loadBundle(json); return; }
      var graph = pendingGraph || (current && current.graph);
      if (!graph) {
        // A standalone report still has every node id in its paths; build a
        // minimal graph from those so the view remains useful.
        graph = graphFromReport(json);
      }
      renderAccount({ name: json.account || "account", graph: graph, report: json });
    });
  }

  function readJsonFile(file, cb) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () { cb(JSON.parse(reader.result)); };
    reader.readAsText(file);
  }

  function emptyReport() {
    return { paths: [], summary: {}, sensitive_resources: [] };
  }

  function graphFromReport(report) {
    var ids = {};
    var edgeIds = {};
    var elements = [];
    (report.accounts || [report]).forEach(function (acc) {
      (acc.paths || []).forEach(function (path) {
        (path.nodes || []).forEach(function (id) {
          if (!ids[id]) { ids[id] = true; elements.push({ data: { id: id, name: shortId(id) } }); }
        });
        (path.hops || []).forEach(function (hop) {
          var key = edgeKey(hop.source, hop.target);
          if (!edgeIds[key]) {
            edgeIds[key] = true;
            elements.push({ data: { source: hop.source, target: hop.target } });
          }
        });
      });
    });
    return elements;
  }

  function normalizeGraph(graph) {
    if (graph && !Array.isArray(graph) && graph.elements) {
      if (Array.isArray(graph.elements)) return graph.elements;
      return (graph.elements.nodes || []).concat(graph.elements.edges || []);
    }
    return graph || [];
  }

  function renderAccount(account) {
    current = account;
    edgeEvidence = {};
    var report = account.report || emptyReport();
    var paths = report.paths || [];

    var sensitiveIds = {};
    (report.sensitive_resources || []).forEach(function (r) { sensitiveIds[r.id] = true; });

    var unionNodes = {}, unionEdges = {};
    paths.forEach(function (path) {
      (path.nodes || []).forEach(function (id) { unionNodes[id] = true; });
      (path.hops || []).forEach(function (hop) {
        var key = edgeKey(hop.source, hop.target);
        unionEdges[key] = true;
        edgeEvidence[key] = hop;
      });
    });

    var graph = normalizeGraph(account.graph);
    var elements = graph.map(function (el) {
      var d = el.data || el;
      var data = Object.assign({}, d);
      if (!data.label) data.label = shortId(data.name || data.id);
      var classes;
      if (d.source !== undefined && d.target !== undefined) {
        var key = edgeKey(d.source, d.target);
        classes = unionEdges[key] ? "path-edge" : "base-edge";
        if (unionEdges[key] && edgeEvidence[key] && !data.label) {
          data.label = edgeEvidence[key].port || "";
        }
      } else {
        var classList = ["base-node"];
        if (d.id === "0.0.0.0/0" || d.type === "cloud") classList.push("internet");
        if (sensitiveIds[d.id]) classList.push("sensitive");
        if (unionNodes[d.id]) classList.push("on-path");
        classes = classList.join(" ");
      }
      return { data: data, classes: classes };
    });

    renderSummary(report, paths);
    renderPathCards(paths);

    if (cy) { cy.destroy(); cy = null; }
    var cyContainer = document.getElementById("cy");
    cy = cytoscape({
      container: cyContainer,
      elements: elements,
      wheelSensitivity: 0.2,
      style: [
        { selector: "node", style: {
          "background-color": "#334155", label: "data(label)", color: "#e2e8f0",
          "font-size": "10px", "text-wrap": "wrap", "text-max-width": "120px",
          "text-valign": "bottom", "text-margin-y": 4,
          "border-width": 1, "border-color": "#475569"
        }},
        { selector: ".internet", style: { "background-color": "#0284c7", shape: "round-rectangle", "font-weight": 700 }},
        { selector: ".sensitive", style: { "border-color": "#ef4444", "border-width": 3, "background-color": "#7f1d1d" }},
        { selector: ".on-path", style: { "background-color": "#0369a1", "border-color": "#38bdf8", "border-width": 2 }},
        { selector: ".selected-node", style: { "background-color": "#38bdf8", color: "#082f49", "font-weight": 700 }},
        { selector: ".target-node", style: { "background-color": "#ef4444", "border-color": "#fecaca", "border-width": 3 }},
        { selector: ".dim", style: { opacity: 0.12 }},
        { selector: "edge", style: {
          width: 1.2, "line-color": "#334155", "target-arrow-color": "#334155",
          "target-arrow-shape": "triangle", "curve-style": "bezier",
          label: "data(label)", "font-size": 9, color: "#7dd3fc",
          "text-background-color": "#0f172a", "text-background-opacity": 0.85,
          "text-background-padding": 2
        }},
        { selector: ".path-edge", style: { width: 3, "line-color": "#38bdf8", "target-arrow-color": "#38bdf8" }},
        { selector: ".selected-edge", style: { width: 5, "line-color": "#22d3ee", "target-arrow-color": "#22d3ee" }},
        { selector: "edge.dim", style: { opacity: 0.08 } }
      ],
      layout: { name: "breadthfirst", directed: true, padding: 28, spacingFactor: 1.15, animate: false }
    });

    cy.on("tap", "node", function (evt) { showNodeDetails(evt.target.data()); });
    cy.on("tap", "edge", function (evt) { showEdgeDetails(evt.target.data()); });
    cy.on("tap", function (evt) { if (evt.target === cy) resetHighlight(); });

    setStatus((account.name || "account") + ": " + paths.length + " path(s)");
  }

  function renderSummary(report, paths) {
    var s = report.summary || {};
    summaryEl.innerHTML =
      "Sensitive resources <b>" + (s.sensitive_resources != null ? s.sensitive_resources : (report.sensitive_resources || []).length) +
      "</b><br/>Reachable sensitive <b>" + (s.reachable_sensitive_resources != null ? s.reachable_sensitive_resources : "?") +
      "</b> &middot; paths <b>" + paths.length + "</b>" +
      (s.verified_paths != null ? " &middot; rule-verified <b>" + s.verified_paths + "</b>" : "");
  }

  function renderPathCards(paths) {
    pathsEl.innerHTML = "";
    if (!paths.length) {
      pathsEl.innerHTML = '<div class="hint">No internet-to-sensitive paths found. &#128737;&#65039;</div>';
      return;
    }
    paths.forEach(function (path) {
      var card = document.createElement("div");
      card.className = "path-card";
      card.style.borderLeftColor = riskColor(path.risk);
      var title = document.createElement("div");
      title.className = "path-title";
      title.innerHTML = "<span>" + path.id + " &rarr; " + escapeHtml(shortId(path.target)) +
        "</span><span class='badge " + (path.risk || "review") + "'>" + (path.risk || "?") + "</span>";
      card.appendChild(title);
      var chain = document.createElement("div");
      chain.className = "chain";
      chain.textContent = path.nodes.map(shortId).join("  →  ");
      card.appendChild(chain);
      var ports = document.createElement("div");
      ports.className = "ports";
      ports.textContent = (path.hops || []).map(function (h) { return shortId(h.source) + " → :" + (h.port || "all"); }).join("   |   ");
      card.appendChild(ports);
      card.addEventListener("click", function () { highlightPath(path, card); });
      pathsEl.appendChild(card);
    });
  }

  function riskColor(risk) {
    return { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" }[risk] || "#64748b";
  }

  function clearCardActive() {
    Array.prototype.forEach.call(document.querySelectorAll(".path-card"), function (c) { c.classList.remove("active"); });
  }

  function highlightPath(path, card) {
    if (!cy) return;
    clearCardActive();
    if (card) card.classList.add("active");
    var nodeSet = {};
    (path.nodes || []).forEach(function (id) { nodeSet[id] = true; });
    var edgeSet = {};
    (path.hops || []).forEach(function (h) { edgeSet[edgeKey(h.source, h.target)] = h; });

    cy.batch(function () {
      cy.nodes().removeClass("selected-node target-node dim");
      cy.edges().removeClass("selected-edge dim");
      cy.nodes().forEach(function (n) {
        if (!nodeSet[n.id()]) n.addClass("dim");
      });
      cy.edges().forEach(function (e) {
        var key = edgeKey(e.data("source"), e.data("target"));
        if (edgeSet[key]) e.addClass("selected-edge");
        else e.addClass("dim");
      });
      var target = cy.getElementById(path.target);
      if (target && target.length) target.addClass("target-node");
    });
    detailsEl.innerHTML = "<b>Selected " + path.id + "</b><br/>Risk: <code>" + path.risk +
      "</code>, confidence: <code>" + path.confidence + "</code><br/>" +
      (path.hops || []).map(function (h) {
        return "hop " + h.hop + ": <code>" + escapeHtml(shortId(h.source)) + " → " +
          escapeHtml(shortId(h.target)) + "</code> " + (h.port || "all") +
          " via " + (h.source_kind || "rule") +
          (h.security_group ? " (<code>" + h.security_group + "</code>)" : "");
      }).join("<br/>");
    cy.fit(cy.elements().not(".dim"), 60);
  }

  function showAllPaths() {
    clearCardActive();
    if (!cy) return;
    cy.batch(function () {
      cy.elements().removeClass("dim selected-node selected-edge target-node");
    });
    detailsEl.textContent = "Showing all reachable paths.";
    cy.fit(cy.elements(".on-path, .path-edge"), 60);
  }

  function resetHighlight() { showAllPaths(); }

  function showNodeDetails(data) {
    var hops = [];
    Object.keys(edgeEvidence).forEach(function (key) {
      var hop = edgeEvidence[key];
      if (hop.source === data.id || hop.target === data.id) hops.push(hop);
    });
    detailsEl.innerHTML = "<b>" + escapeHtml(String(data.name || data.id)) + "</b><br/>type: <code>" +
      escapeHtml(String(data.type || "?")) + "</code><br/>id: <code>" + escapeHtml(String(data.id)) + "</code>" +
      (hops.length ? "<br/><br/>Security-group evidence:<br/>" + hops.map(function (h) {
        return "<code>" + h.port + "</code> " + h.source_kind +
          (h.source_value ? ":" + escapeHtml(h.source_value) : "") +
          (h.security_group ? " SG <code>" + h.security_group + "</code>" : "");
      }).join("<br/>") : "");
  }

  function showEdgeDetails(data) {
    var hop = edgeEvidence[edgeKey(data.source, data.target)];
    if (!hop) { detailsEl.textContent = "Topology edge (not part of an internet path)."; return; }
    detailsEl.innerHTML = "<b>Hop " + hop.hop + "</b><br/><code>" +
      escapeHtml(shortId(hop.source)) + " → " + escapeHtml(shortId(hop.target)) +
      "</code><br/>open: <code>" + (hop.port || "all") + "</code><br/>reason: " +
      (hop.source_kind || "?") + " <code>" + escapeHtml(hop.source_value || "") + "</code><br/>security group: <code>" +
      escapeHtml(hop.security_group || hop.security_group_name || "edge") + "</code><br/>verified: <code>" +
      hop.verified + "</code>";
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
