// Strata's built-in chat page (listener.web_ui). Bundled into the server binary; it talks
// only to this origin. The API key is the login: kept in sessionStorage (this tab only) and
// sent only as "Authorization: Bearer" to this server's /v1 routes. On a keyless loopback
// server (listener.loopback_without_key) the probe below succeeds without a key and the
// login is skipped. Model output is always rendered as text (textContent), never as HTML.
(function () {
  "use strict";

  var KEY_SLOT = "strata.apiKey";
  var state = { key: null, keyless: false, history: [], controller: null };

  function byId(id) { return document.getElementById(id); }

  function storedKey() {
    try { return window.sessionStorage.getItem(KEY_SLOT); } catch (e) { return null; }
  }
  function storeKey(value) {
    try {
      if (value) { window.sessionStorage.setItem(KEY_SLOT, value); } else { window.sessionStorage.removeItem(KEY_SLOT); }
    } catch (e) { /* storage blocked: the key lives in memory for this page only */ }
  }

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
      if (parsed && parsed.error && parsed.error.message) {
        return parsed.error.message + " (" + (parsed.error.code || status) + ")";
      }
    } catch (e) { /* not JSON */ }
    return "HTTP " + status;
  }

  function showLogin(message) {
    byId("app").hidden = true;
    byId("login").hidden = false;
    byId("login-error").textContent = message || "";
    byId("key").value = "";
    byId("key").focus();
  }

  function showApp(models) {
    var select = byId("model");
    while (select.firstChild) { select.removeChild(select.firstChild); }
    models.forEach(function (model) {
      var option = document.createElement("option");
      option.value = model.id;
      option.textContent = model.id;
      select.appendChild(option);
    });
    byId("mode").textContent = state.keyless ? "No API key needed (loopback server)" : "";
    byId("sign-out").hidden = state.keyless;
    byId("login").hidden = true;
    byId("app").hidden = false;
    byId("prompt").focus();
  }

  // Lists the models with the current credentials; resolves to the list, or null on 401.
  async function listModels() {
    var response = await api("/v1/models");
    var body = await response.text();
    if (response.status === 401) { return null; }
    if (!response.ok) { throw new Error(errorText(response.status, body)); }
    var parsed = JSON.parse(body);
    return parsed && Array.isArray(parsed.data) ? parsed.data : [];
  }

  async function signIn(key) {
    state.key = key;
    byId("login-error").textContent = "";
    var models;
    try { models = await listModels(); } catch (e) { showLogin("Cannot reach the server: " + e.message); return; }
    if (models === null) {
      state.key = null;
      storeKey(null);
      showLogin("That API key was not accepted.");
      return;
    }
    storeKey(key);
    state.keyless = false;
    showApp(models);
  }

  function signOut(message) {
    if (state.controller) { state.controller.abort(); }
    state.key = null;
    storeKey(null);
    newChat();
    showLogin(message);
  }

  function newChat() {
    state.history = [];
    var messages = byId("messages");
    while (messages.firstChild) { messages.removeChild(messages.firstChild); }
    byId("status").textContent = "";
  }

  function addMessage(role, text) {
    var item = document.createElement("article");
    item.className = "message " + role;
    var who = document.createElement("div");
    who.className = "who";
    who.textContent = role === "user" ? "You" : "Assistant";
    item.appendChild(who);
    var parts = { item: item, thinking: null, thinkingText: null, answer: document.createElement("div"), meta: null };
    if (role === "assistant") {
      parts.thinking = document.createElement("details");
      parts.thinking.className = "thinking";
      parts.thinking.hidden = true;
      var summary = document.createElement("summary");
      summary.textContent = "Thinking";
      parts.thinking.appendChild(summary);
      parts.thinkingText = document.createElement("div");
      parts.thinkingText.className = "text";
      parts.thinking.appendChild(parts.thinkingText);
      item.appendChild(parts.thinking);
    }
    parts.answer.className = "text";
    parts.answer.textContent = text || "";
    item.appendChild(parts.answer);
    if (role === "assistant") {
      parts.meta = document.createElement("div");
      parts.meta.className = "meta muted small";
      item.appendChild(parts.meta);
    }
    byId("messages").appendChild(item);
    item.scrollIntoView({ block: "end" });
    return parts;
  }

  function busy(on) {
    byId("send").disabled = on;
    byId("stop").hidden = !on;
    byId("prompt").disabled = on;
  }

  // One SSE event: "data: <json>" lines; returns true at [DONE].
  function handleEvent(text, parts, run) {
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i];
      if (line.indexOf("data: ") !== 0) { continue; }
      var data = line.slice(6);
      if (data === "[DONE]") { return true; }
      var event;
      try { event = JSON.parse(data); } catch (e) { continue; }
      if (event.error) { run.error = (event.error.message || "error") + " (" + (event.error.code || "") + ")"; continue; }
      if (event.usage) { run.usage = event.usage; }
      var choice = event.choices && event.choices[0];
      if (!choice) { continue; }
      var delta = choice.delta || {};
      if (delta.reasoning_content) {
        parts.thinking.hidden = false;
        parts.thinkingText.textContent += delta.reasoning_content;
      }
      if (delta.content) {
        run.answer += delta.content;
        parts.answer.textContent = run.answer;
      }
      if (choice.finish_reason) { run.finish = choice.finish_reason; }
    }
    return false;
  }

  async function send(text) {
    state.history.push({ role: "user", content: text });
    addMessage("user", text);
    var parts = addMessage("assistant", "");
    var run = { answer: "", finish: "", usage: null, error: "" };
    var payload = {
      model: byId("model").value,
      messages: state.history,
      stream: true,
      stream_options: { include_usage: true }
    };
    var maxTokens = parseInt(byId("max-tokens").value, 10);
    if (maxTokens > 0) { payload.max_tokens = maxTokens; }
    state.controller = new AbortController();
    var started = performance.now();
    busy(true);
    byId("status").textContent = "Waiting for the model...";
    try {
      var response = await api("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: state.controller.signal
      });
      if (response.status === 401 && !state.keyless) {
        signOut("The server no longer accepts this API key.");
        return;
      }
      if (!response.ok) {
        run.error = errorText(response.status, await response.text());
      } else {
        byId("status").textContent = "";
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
            done = handleEvent(buffer.slice(0, boundary), parts, run);
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf("\n\n");
          }
          parts.item.scrollIntoView({ block: "end" });
        }
      }
    } catch (e) {
      run.error = e && e.name === "AbortError" ? "stopped" : "request failed: " + (e && e.message ? e.message : e);
    } finally {
      state.controller = null;
      busy(false);
      byId("prompt").focus();
    }
    if (run.answer) { state.history.push({ role: "assistant", content: run.answer }); } else { state.history.pop(); }
    var seconds = (performance.now() - started) / 1000;
    var meta = [];
    if (run.finish) { meta.push(run.finish); }
    if (run.usage && run.usage.completion_tokens) {
      meta.push(run.usage.completion_tokens + " tokens, " + (run.usage.completion_tokens / seconds).toFixed(1) + " tok/s");
    }
    meta.push(seconds.toFixed(1) + " s");
    if (run.error) { meta.push(run.error); parts.meta.classList.add("error"); }
    parts.meta.textContent = meta.join(" | ");
    byId("status").textContent = "";
  }

  function submitPrompt() {
    var prompt = byId("prompt");
    var text = prompt.value.trim();
    if (!text || state.controller) { return; }
    prompt.value = "";
    send(text);
  }

  async function start() {
    byId("login-form").addEventListener("submit", function (event) {
      event.preventDefault();
      var key = byId("key").value.trim();
      if (!key) { byId("login-error").textContent = "Enter the API key."; return; }
      signIn(key);
    });
    byId("composer").addEventListener("submit", function (event) { event.preventDefault(); submitPrompt(); });
    byId("prompt").addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); submitPrompt(); }
    });
    byId("stop").addEventListener("click", function () { if (state.controller) { state.controller.abort(); } });
    byId("new-chat").addEventListener("click", function () { if (!state.controller) { newChat(); } });
    byId("sign-out").addEventListener("click", function () { signOut(""); });

    var key = storedKey();
    if (key) { await signIn(key); return; }
    // Keyless loopback server: the model list answers without a key.
    try {
      var models = await listModels();
      if (models !== null) { state.keyless = true; showApp(models); return; }
    } catch (e) {
      showLogin("Cannot reach the server: " + e.message);
      return;
    }
    showLogin("");
  }

  start();
}());
