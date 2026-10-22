// Strata's built-in chat page (listener.web_ui), modelled on upstream Strata's serve/web UI (pin
// v0.2.2, MIT License, Copyright (c) 2026 Niko1221 and the Strata contributors; see
// LICENSE.strata-ui.txt) and written for this server's routes: /health, /v1/models and
// /v1/chat/completions, nothing else.
//
// The API key is the login: kept in sessionStorage (this tab only) and sent only as
// "Authorization: Bearer" to this origin, with cookies off. On a keyless loopback server
// (listener.loopback_without_key) the model list answers without a key and the login is skipped.
// Model output is never parsed as HTML: the Markdown renderer below builds DOM nodes and sets
// text with textContent.
(function () {
  "use strict";

  var SLOT_KEY = "strata.apiKey";
  var SLOT_CHAT = "strata.chat";
  var SLOT_SETTINGS = "strata.settings";
  var DEFAULTS = { thinking: "on", temperature: 1.0, top_p: 0.95, max: "", seed: "", show: true, tuned: false };
  var SPRITE = "/ui/sprite.svg#";

  var state = {
    key: null, keyless: false, models: [], model: "", history: [], attachments: [],
    controller: null, settings: null, health: null, pollTimer: null
  };

  function $(id) { return document.getElementById(id); }

  // ---------------------------------------------------------------- storage (this tab only)
  function load(slot, fallback) {
    try {
      var text = window.sessionStorage.getItem(slot);
      return text === null ? fallback : JSON.parse(text);
    } catch (e) { return fallback; }
  }
  function save(slot, value) {
    try {
      if (value === null) { window.sessionStorage.removeItem(slot); } else { window.sessionStorage.setItem(slot, JSON.stringify(value)); }
    } catch (e) { /* storage blocked: kept in memory for this page only */ }
  }

  // ---------------------------------------------------------------- small DOM helpers
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }
  function icon(name, small) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", small ? "st-icon st-icon--sm" : "st-icon");
    var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", SPRITE + name);
    svg.appendChild(use);
    return svg;
  }
  function iconButton(name, label, onClick) {
    var button = el("button", "st-btn st-btn--icon");
    button.type = "button";
    button.title = label;
    button.setAttribute("aria-label", label);
    button.appendChild(icon(name));
    button.addEventListener("click", onClick);
    return button;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function toast(kind, title, text) {
    var box = el("div", "st-toast st-toast--" + kind);
    box.appendChild(icon(kind === "error" ? "i-error" : kind === "success" ? "i-check" : "i-info"));
    var body = el("div");
    body.appendChild(el("div", "st-toast__title", title));
    if (text) { body.appendChild(el("div", null, text)); }
    box.appendChild(body);
    $("toasts").appendChild(box);
    window.setTimeout(function () { if (box.parentNode) { box.parentNode.removeChild(box); } }, 4000);
  }

  // Clipboard: the async API needs a secure context, which a page served over plain HTTP on the
  // LAN is not; the fallback copies from a hidden text area.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { toast("success", "Copied"); },
        function () { toast("error", "Could not copy"); });
      return;
    }
    var area = el("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "copy-buffer";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    toast(ok ? "success" : "error", ok ? "Copied" : "Could not copy");
  }

  // ---------------------------------------------------------------- API
  function api(path, options) {
    var init = options || {};
    var headers = init.headers || {};
    if (state.key) { headers.Authorization = "Bearer " + state.key; }
    init.headers = headers;
    init.cache = "no-store";
    init.credentials = "omit";
    init.referrerPolicy = "no-referrer";
    return window.fetch(path, init);
  }
  function errorText(status, body) {
    try {
      var parsed = JSON.parse(body);
      if (parsed && parsed.error && parsed.error.message) { return parsed.error.message + " (" + (parsed.error.code || status) + ")"; }
    } catch (e) { /* not JSON */ }
    return "HTTP " + status;
  }
  // The model list with the current credentials: the list, or null on 401.
  async function listModels() {
    var response = await api("/v1/models");
    var body = await response.text();
    if (response.status === 401) { return null; }
    if (!response.ok) { throw new Error(errorText(response.status, body)); }
    var parsed = JSON.parse(body);
    return parsed && Array.isArray(parsed.data) ? parsed.data.map(function (m) { return m.id; }) : [];
  }

  // ---------------------------------------------------------------- views
  function showView(name) {
    ["login", "chat", "about"].forEach(function (view) { $("view-" + view).hidden = view !== name; });
    var signedIn = name !== "login";
    $("tabs").hidden = !signedIn;
    $("new-btn").hidden = name !== "chat";
    ["chat", "about"].forEach(function (tab) { $("tab-btn-" + tab).setAttribute("aria-selected", tab === name ? "true" : "false"); });
    if (name === "about") { renderAbout(); }
    if (name === "chat") { $("input").focus(); }
  }
  function showLogin(message) {
    stopPolling();
    setPill("idle", "Signed out");
    $("login-error").textContent = message || "";
    $("login-error").hidden = !message;
    $("key").value = "";
    showView("login");
    $("key").focus();
  }
  function enterApp(models) {
    state.models = models;
    state.model = models.length ? models[0] : "";
    $("sign-out-row").hidden = state.keyless;
    renderChat();
    showView("chat");
    startPolling();
  }

  async function signIn(key) {
    state.key = key;
    $("sign-in").disabled = true;
    var models;
    try { models = await listModels(); } catch (e) { $("sign-in").disabled = false; showLogin("Cannot reach the server: " + e.message); return; }
    $("sign-in").disabled = false;
    if (models === null) { state.key = null; save(SLOT_KEY, null); showLogin("That API key was not accepted."); return; }
    save(SLOT_KEY, key);
    state.keyless = false;
    enterApp(models);
  }
  function signOut(message) {
    if (state.controller) { state.controller.abort(); }
    state.key = null;
    save(SLOT_KEY, null);
    newChat();
    showLogin(message || "");
  }

  // ---------------------------------------------------------------- status pill (/health)
  function setPill(stateName, text) {
    $("pill").setAttribute("data-state", stateName);
    $("pill-text").textContent = text;
  }
  async function pollHealth() {
    if (state.controller) { return; }  // the chat itself drives the pill while it runs
    try {
      var response = await api("/health");
      var parsed = JSON.parse(await response.text());
      state.health = parsed;
      var engine = parsed && parsed.engine;
      if (response.status === 401) { setPill("idle", "Key needed"); }
      else if (engine === "ready") { setPill("idle", "Ready"); }
      else if (engine === "generating") { setPill("generating", "Busy"); }
      else if (engine === "starting") { setPill("queued", "Starting"); }
      else { setPill("queued", engine === "failed" ? "Engine error" : "Unavailable"); }
    } catch (e) { setPill("idle", "Offline"); }
  }
  function startPolling() { stopPolling(); pollHealth(); state.pollTimer = window.setInterval(pollHealth, 5000); }
  function stopPolling() { if (state.pollTimer) { window.clearInterval(state.pollTimer); state.pollTimer = null; } }

  // ---------------------------------------------------------------- Markdown (DOM only)
  function inline(parent, text) {
    // `code`, **bold**, *italic*/_italic_, [label](http(s)://...) - everything else is text.
    var pattern = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*|__[^_\n]+__)|(\*[^*\n]+\*|_[^_\n]+_)|(\[[^\]\n]+\]\(https?:\/\/[^)\s]+\))/g;
    var last = 0;
    var match;
    while ((match = pattern.exec(text)) !== null) {
      if (match.index > last) { parent.appendChild(document.createTextNode(text.slice(last, match.index))); }
      var token = match[0];
      if (match[1]) { parent.appendChild(el("code", "inline", token.slice(1, -1))); }
      else if (match[2]) { var strong = el("strong"); inline(strong, token.slice(2, -2)); parent.appendChild(strong); }
      else if (match[3]) { var em = el("em"); inline(em, token.slice(1, -1)); parent.appendChild(em); }
      else {
        var close = token.indexOf("](");
        var link = el("a", null, token.slice(1, close));
        link.href = token.slice(close + 2, -1);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        parent.appendChild(link);
      }
      last = match.index + token.length;
    }
    if (last < text.length) { parent.appendChild(document.createTextNode(text.slice(last))); }
  }
  function codeBlock(language, code) {
    var box = el("div", "st-code");
    var head = el("div", "st-code__head");
    head.appendChild(el("span", null, language || "code"));
    head.appendChild(iconButton("i-copy", "Copy code", function () { copyText(code); }));
    box.appendChild(head);
    var pre = el("pre");
    pre.appendChild(el("code", null, code));
    box.appendChild(pre);
    return box;
  }
  function tableRow(line) {
    var cells = line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|");
    return cells.map(function (cell) { return cell.trim(); });
  }
  function renderMarkdown(target, text) {
    clear(target);
    var lines = text.replace(/\r\n/g, "\n").split("\n");
    var i = 0;
    var paragraph = [];
    function flush() {
      if (!paragraph.length) { return; }
      var p = el("p");
      paragraph.forEach(function (line, index) { if (index) { p.appendChild(el("br")); } inline(p, line); });
      target.appendChild(p);
      paragraph = [];
    }
    while (i < lines.length) {
      var line = lines[i];
      var fence = /^\s*(```|~~~)\s*([\w+#.-]*)\s*$/.exec(line);
      if (fence) {
        flush();
        var body = [];
        i += 1;
        while (i < lines.length && lines[i].trim() !== fence[1]) { body.push(lines[i]); i += 1; }
        target.appendChild(codeBlock(fence[2], body.join("\n")));
        i += 1;
        continue;
      }
      var heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) { flush(); var h = el(heading[1].length <= 2 ? "h3" : "h4"); inline(h, heading[2]); target.appendChild(h); i += 1; continue; }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { flush(); target.appendChild(el("hr")); i += 1; continue; }
      if (/^\s*>/.test(line)) {
        flush();
        var quote = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) { quote.push(lines[i].replace(/^\s*>\s?/, "")); i += 1; }
        var blockquote = el("blockquote");
        renderMarkdown(blockquote, quote.join("\n"));
        target.appendChild(blockquote);
        continue;
      }
      if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
        flush();
        var wrap = el("div", "table-wrap");
        var table = el("table");
        var headRow = el("tr");
        tableRow(line).forEach(function (cell) { var th = el("th"); inline(th, cell); headRow.appendChild(th); });
        var thead = el("thead"); thead.appendChild(headRow); table.appendChild(thead);
        var tbody = el("tbody");
        i += 2;
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
          var row = el("tr");
          tableRow(lines[i]).forEach(function (cell) { var td = el("td"); inline(td, cell); row.appendChild(td); });
          tbody.appendChild(row);
          i += 1;
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        target.appendChild(wrap);
        continue;
      }
      var bullet = /^\s*([-*+]|\d+[.)])\s+(.*)$/.exec(line);
      if (bullet) {
        flush();
        var ordered = /\d/.test(bullet[1]);
        var list = el(ordered ? "ol" : "ul");
        while (i < lines.length) {
          var item = /^\s*([-*+]|\d+[.)])\s+(.*)$/.exec(lines[i]);
          if (!item || /\d/.test(item[1]) !== ordered) { break; }
          var li = el("li"); inline(li, item[2]); list.appendChild(li);
          i += 1;
        }
        target.appendChild(list);
        continue;
      }
      if (line.trim() === "") { flush(); i += 1; continue; }
      paragraph.push(line);
      i += 1;
    }
    flush();
  }

  // ---------------------------------------------------------------- chat rendering
  function messageNode(message) {
    var node = el("div", "st-msg st-msg--" + message.role);
    var parts = { node: node, thinking: null, thinkingBody: null, bubble: null, meta: null };
    if (message.role === "assistant") {
      var details = el("details", "st-collapse");
      var summary = el("summary");
      summary.appendChild(icon("i-thinking", true));
      summary.appendChild(el("span", null, "Thinking"));
      var chevron = icon("i-chevron", true);
      chevron.setAttribute("class", "st-icon st-icon--sm st-chev");
      summary.appendChild(chevron);
      details.appendChild(summary);
      parts.thinkingBody = el("div", "st-collapse__body thinking", message.reasoning || "");
      details.appendChild(parts.thinkingBody);
      details.hidden = !message.reasoning;
      parts.thinking = details;
      node.appendChild(details);
    }
    parts.bubble = el("div", "st-bubble");
    if (message.role === "assistant") { renderMarkdown(parts.bubble, message.content || ""); } else { parts.bubble.textContent = message.content; }
    node.appendChild(parts.bubble);
    parts.meta = el("div", "st-msg__meta");
    fillMeta(parts, message);
    node.appendChild(parts.meta);
    return parts;
  }
  function fillMeta(parts, message) {
    clear(parts.meta);
    if (message.role === "assistant" && message.stats) { parts.meta.appendChild(el("span", null, message.stats)); }
    if (message.error) { parts.meta.appendChild(el("p", "msg-error", message.error)); }
    if (message.content) {
      parts.meta.appendChild(iconButton("i-copy", "Copy", function () { copyText(message.content); }));
    }
  }
  function renderChat() {
    var chat = $("chat");
    Array.prototype.slice.call(chat.querySelectorAll(".st-msg")).forEach(function (node) { chat.removeChild(node); });
    $("chat-empty").hidden = state.history.length > 0;
    state.history.forEach(function (message) { chat.appendChild(messageNode(message).node); });
    scrollToEnd();
  }
  function scrollToEnd() { var scroll = $("chat-scroll"); scroll.scrollTop = scroll.scrollHeight; }
  function newChat() {
    if (state.controller) { return; }
    state.history = [];
    state.attachments = [];
    save(SLOT_CHAT, null);
    renderAttachments();
    renderChat();
    $("composer-hint").textContent = "";
    $("input").focus();
  }

  // ---------------------------------------------------------------- attachments (text files)
  function renderAttachments() {
    var box = $("attachments");
    clear(box);
    box.hidden = state.attachments.length === 0;
    state.attachments.forEach(function (file, index) {
      var chip = el("span", "chip", file.name);
      chip.appendChild(iconButton("i-trash", "Remove " + file.name, function () { state.attachments.splice(index, 1); renderAttachments(); }));
      box.appendChild(chip);
    });
  }
  function addFiles(files) {
    Array.prototype.forEach.call(files, function (file) {
      var reader = new FileReader();
      reader.onload = function () {
        var text = String(reader.result || "");
        if (text.indexOf("\u0000") >= 0) { toast("error", "Not a text file", file.name); return; }
        state.attachments.push({ name: file.name, text: text });
        renderAttachments();
      };
      reader.onerror = function () { toast("error", "Could not read", file.name); };
      reader.readAsText(file);
    });
  }

  // ---------------------------------------------------------------- sending
  function busy(on) {
    $("send-btn").hidden = on;
    $("stop-btn").hidden = !on;
    $("new-btn").disabled = on;
  }
  // What the server takes: user and assistant turns in strict alternation (this page sends no
  // system turn). A question that never got an answer, as in a chat saved by an older page,
  // would make every later request a 400 (session log issue 40), so the newer question takes
  // its place.
  function conversation(history) {
    var turns = [];
    history.forEach(function (m) {
      if (!m || typeof m.content !== "string" || !m.content) { return; }
      var last = turns.length ? turns[turns.length - 1].role : "";
      if (m.role === "user" && last === "user") {
        turns[turns.length - 1] = m;
      } else if (m.role === "user" || (m.role === "assistant" && last === "user")) {
        turns.push(m);
      }
    });
    return turns;
  }
  function requestBody() {
    var s = state.settings;
    var body = {
      model: state.model,
      messages: conversation(state.history).map(function (m) { return { role: m.role, content: m.content }; }),
      stream: true,
      stream_options: { include_usage: true },
      reasoning_effort: s.thinking === "off" ? "none" : "high"
    };
    if (s.tuned) { body.temperature = Number(s.temperature); body.top_p = Number(s.top_p); }
    if (s.max) { body.max_tokens = Number(s.max); }
    if (s.seed) { body.seed = Number(s.seed); }
    return body;
  }
  function handleEvent(text, run, parts) {
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      if (lines[i].indexOf("data: ") !== 0) { continue; }
      var data = lines[i].slice(6);
      if (data === "[DONE]") { return true; }
      var event;
      try { event = JSON.parse(data); } catch (e) { continue; }
      if (event.error) { run.error = (event.error.message || "error") + " (" + (event.error.code || "") + ")"; continue; }
      if (event.usage) { run.usage = event.usage; }
      var choice = event.choices && event.choices[0];
      if (!choice) { continue; }
      var delta = choice.delta || {};
      if (delta.reasoning_content) {
        if (!run.firstToken) { run.firstToken = performance.now(); setPill("generating", "Thinking"); }
        run.reasoning += delta.reasoning_content;
        parts.thinking.hidden = false;
        if (state.settings.show && !run.answer) { parts.thinking.open = true; }
        parts.thinkingBody.textContent = run.reasoning;
      }
      if (delta.content) {
        if (!run.firstToken) { run.firstToken = performance.now(); }
        if (!run.answer && parts.thinking.open && run.reasoning) { parts.thinking.open = false; }
        setPill("generating", "Writing");
        run.answer += delta.content;
        run.dirty = true;
      }
      if (choice.finish_reason) { run.finish = choice.finish_reason; }
    }
    return false;
  }
  async function send(text) {
    var content = text;
    if (state.attachments.length) {
      var blocks = state.attachments.map(function (file) { return "File " + file.name + ":\n```\n" + file.text + "\n```"; });
      content = blocks.join("\n\n") + (text ? "\n\n" + text : "");
      state.attachments = [];
      renderAttachments();
    }
    var user = { role: "user", content: content };
    state.history.push(user);
    $("chat-empty").hidden = true;
    $("chat").appendChild(messageNode(user).node);
    var reply = { role: "assistant", content: "", reasoning: "", stats: "", error: "" };
    var parts = messageNode(reply);
    parts.bubble.classList.add("cursor");
    $("chat").appendChild(parts.node);
    scrollToEnd();
    var run = { answer: "", reasoning: "", finish: "", usage: null, error: "", firstToken: 0, dirty: false };
    state.controller = new AbortController();
    var started = performance.now();
    busy(true);
    setPill("reading", "Reading");
    $("composer-hint").textContent = "";
    var painter = window.setInterval(function () {
      if (run.dirty) { run.dirty = false; renderMarkdown(parts.bubble, run.answer); scrollToEnd(); }
    }, 80);
    try {
      var response = await api("/v1/chat/completions", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody()), signal: state.controller.signal
      });
      if (response.status === 401 && !state.keyless) {
        window.clearInterval(painter);
        state.controller = null;
        busy(false);
        state.history.pop();
        signOut("The server no longer accepts this API key.");
        return;
      }
      if (!response.ok) {
        run.error = errorText(response.status, await response.text());
      } else {
        var reader = response.body.getReader();
        var decoder = new TextDecoder();
        var buffer = "";
        var done = false;
        while (!done) {
          var chunk = await reader.read();
          if (chunk.done) { break; }
          buffer += decoder.decode(chunk.value, { stream: true });
          var boundary = buffer.indexOf("\n\n");
          while (boundary >= 0 && !done) {
            done = handleEvent(buffer.slice(0, boundary), run, parts);
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf("\n\n");
          }
        }
      }
    } catch (e) {
      run.error = e && e.name === "AbortError" ? "Stopped" : "Request failed: " + (e && e.message ? e.message : e);
    }
    window.clearInterval(painter);
    state.controller = null;
    busy(false);
    parts.bubble.classList.remove("cursor");
    renderMarkdown(parts.bubble, run.answer);
    var seconds = (performance.now() - started) / 1000;
    var stats = [];
    if (state.model) { stats.push(state.model); }
    if (run.usage && run.usage.completion_tokens) {
      // The writing speed, from the first token on; a reply of a few tokens can arrive in one
      // chunk, so a rate is shown only when there is enough of it to mean something.
      var tokens = run.usage.completion_tokens;
      var genSeconds = run.firstToken ? (performance.now() - run.firstToken) / 1000 : seconds;
      stats.push(tokens + " tokens");
      if (tokens >= 16 && genSeconds >= 0.25) { stats.push((tokens / genSeconds).toFixed(1) + " tok/s"); }
    }
    stats.push(seconds.toFixed(1) + " s");
    if (run.finish && run.finish !== "stop") { stats.push(run.finish); }
    reply.content = run.answer;
    reply.reasoning = run.reasoning;
    reply.stats = stats.join(" - ");
    reply.error = run.error;
    // A turn with an answer stands (a stopped one keeps its text). Without one, the question
    // leaves the conversation (it stays on screen with the error): the server takes
    // alternating user/assistant turns, so two questions in a row would be refused.
    if (run.answer) { state.history.push(reply); } else { state.history.pop(); }
    parts.bubble.hidden = !run.answer;
    fillMeta(parts, reply);
    save(SLOT_CHAT, conversation(state.history));
    pollHealth();
    scrollToEnd();
    $("input").focus();
  }
  function submit() {
    var input = $("input");
    var text = input.value.trim();
    if ((!text && !state.attachments.length) || state.controller) { return; }
    input.value = "";
    autosize();
    send(text);
  }
  function autosize() {
    var input = $("input");
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, window.innerHeight * 0.4) + "px";
  }

  // ---------------------------------------------------------------- export
  function exportChat() {
    if (!state.history.length) { toast("info", "Nothing to save yet"); return; }
    var text = "# Strata chat\n\n" + state.history.map(function (m) {
      return (m.role === "user" ? "## You\n\n" : "## " + (state.model || "Assistant") + "\n\n") + m.content;
    }).join("\n\n") + "\n";
    var link = el("a");
    link.href = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
    link.download = "strata-chat.md";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
  }

  // ---------------------------------------------------------------- sampling drawer
  function showSettings() {
    var s = state.settings;
    Array.prototype.forEach.call($("s-thinking").querySelectorAll("button"), function (b) {
      b.setAttribute("aria-checked", b.getAttribute("data-v") === s.thinking ? "true" : "false");
    });
    $("o-thinking").textContent = s.thinking === "off" ? "off" : "on";
    $("s-temp").value = s.temperature; $("o-temp").textContent = Number(s.temperature).toFixed(2);
    $("s-topp").value = s.top_p; $("o-topp").textContent = Number(s.top_p).toFixed(2);
    $("s-max").value = s.max; $("s-seed").value = s.seed;
    $("s-show").setAttribute("aria-checked", s.show ? "true" : "false");
  }
  function openDrawer(open) {
    $("drawer").setAttribute("data-open", open ? "true" : "false");
    $("drawer").setAttribute("aria-hidden", open ? "false" : "true");
    $("scrim").hidden = !open;
    if (open) { showSettings(); }
  }
  function applySettings() {
    var s = state.settings;
    var thinking = $("s-thinking").querySelector("[aria-checked=true]");
    s.thinking = thinking ? thinking.getAttribute("data-v") : "on";
    var temperature = Number($("s-temp").value);
    var topP = Number($("s-topp").value);
    s.tuned = s.tuned || temperature !== s.temperature || topP !== s.top_p;
    s.temperature = temperature;
    s.top_p = topP;
    s.max = $("s-max").value.trim();
    s.seed = $("s-seed").value.trim();
    s.show = $("s-show").getAttribute("aria-checked") === "true";
    save(SLOT_SETTINGS, s);
    openDrawer(false);
    toast("success", "Settings applied");
  }

  // ---------------------------------------------------------------- about
  function fact(list, label, value, copyable) {
    list.appendChild(el("dt", null, label));
    var dd = el("dd");
    var code = el("code", null, value);
    dd.appendChild(code);
    if (copyable) { dd.appendChild(iconButton("i-copy", "Copy " + label, function () { copyText(value); })); }
    list.appendChild(dd);
  }
  function renderAbout() {
    var model = $("facts-model");
    clear(model);
    fact(model, "Model", state.models.length ? state.models.join(", ") : "-", false);
    fact(model, "Engine", state.health && state.health.engine ? state.health.engine : "-", false);
    fact(model, "Server", window.location.origin, false);
    var apiFacts = $("facts-api");
    clear(apiFacts);
    fact(apiFacts, "Base URL", window.location.origin + "/v1", true);
    fact(apiFacts, "Model", state.model || "-", true);
    fact(apiFacts, "API key", state.keyless ? "not needed (loopback server)" : "the key you signed in with", false);
    $("dark-toggle").setAttribute("aria-checked", window.StrataTheme && window.StrataTheme.get() === "dark" ? "true" : "false");
  }

  // ---------------------------------------------------------------- theme
  function syncThemeIcon() {
    var dark = window.StrataTheme && window.StrataTheme.get() === "dark";
    $("theme-icon").setAttribute("href", SPRITE + (dark ? "i-sun" : "i-moon"));
    $("dark-toggle").setAttribute("aria-checked", dark ? "true" : "false");
  }
  function toggleTheme() {
    if (!window.StrataTheme) { return; }
    window.StrataTheme.set(window.StrataTheme.get() === "dark" ? "light" : "dark");
    syncThemeIcon();
  }

  // ---------------------------------------------------------------- wiring
  function wire() {
    $("login-form").addEventListener("submit", function (event) {
      event.preventDefault();
      var key = $("key").value.trim();
      if (!key) { $("login-error").textContent = "Enter the API key."; $("login-error").hidden = false; return; }
      signIn(key);
    });
    $("composer").addEventListener("submit", function (event) { event.preventDefault(); submit(); });
    $("input").addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); submit(); }
    });
    $("input").addEventListener("input", autosize);
    $("stop-btn").addEventListener("click", function () { if (state.controller) { state.controller.abort(); } });
    $("new-btn").addEventListener("click", newChat);
    $("export-btn").addEventListener("click", exportChat);
    $("attach-btn").addEventListener("click", function () { $("file").click(); });
    $("file").addEventListener("change", function () { addFiles($("file").files); $("file").value = ""; });
    var composer = $("composer");
    composer.addEventListener("dragover", function (event) { event.preventDefault(); composer.classList.add("dragging"); });
    composer.addEventListener("dragleave", function () { composer.classList.remove("dragging"); });
    composer.addEventListener("drop", function (event) {
      event.preventDefault();
      composer.classList.remove("dragging");
      if (event.dataTransfer && event.dataTransfer.files) { addFiles(event.dataTransfer.files); }
    });
    $("sampling-btn").addEventListener("click", function () { openDrawer(true); });
    $("drawer-close").addEventListener("click", function () { openDrawer(false); });
    $("scrim").addEventListener("click", function () { openDrawer(false); });
    Array.prototype.forEach.call($("s-thinking").querySelectorAll("button"), function (button) {
      button.addEventListener("click", function () {
        Array.prototype.forEach.call($("s-thinking").querySelectorAll("button"), function (b) {
          b.setAttribute("aria-checked", b === button ? "true" : "false");
        });
        $("o-thinking").textContent = button.getAttribute("data-v");
      });
    });
    $("s-temp").addEventListener("input", function () { $("o-temp").textContent = Number($("s-temp").value).toFixed(2); });
    $("s-topp").addEventListener("input", function () { $("o-topp").textContent = Number($("s-topp").value).toFixed(2); });
    $("s-show").addEventListener("click", function () {
      $("s-show").setAttribute("aria-checked", $("s-show").getAttribute("aria-checked") === "true" ? "false" : "true");
    });
    $("s-reset").addEventListener("click", function () { state.settings = Object.assign({}, DEFAULTS); showSettings(); });
    $("s-apply").addEventListener("click", applySettings);
    $("tab-btn-chat").addEventListener("click", function () { showView("chat"); });
    $("tab-btn-about").addEventListener("click", function () { showView("about"); });
    $("theme-btn").addEventListener("click", toggleTheme);
    $("dark-toggle").addEventListener("click", toggleTheme);
    $("sign-out").addEventListener("click", function () { signOut(""); });
  }

  async function start() {
    state.settings = Object.assign({}, DEFAULTS, load(SLOT_SETTINGS, {}));
    // A saved chat is repaired on the way in: it never ends on an unanswered question.
    var saved = load(SLOT_CHAT, []);
    state.history = Array.isArray(saved) ? conversation(saved) : [];
    if (state.history.length && state.history[state.history.length - 1].role === "user") { state.history.pop(); }
    wire();
    syncThemeIcon();
    var key = load(SLOT_KEY, null);
    if (typeof key === "string" && key) { await signIn(key); return; }
    try {
      var models = await listModels();  // keyless loopback server: the list answers without a key
      if (models !== null) { state.keyless = true; enterApp(models); return; }
    } catch (e) {
      showLogin("Cannot reach the server: " + e.message);
      return;
    }
    showLogin("");
  }

  start();
}());
