"use strict";

(() => {
  if (window.top !== window.self) {
    document.body.replaceChildren();
    return;
  }
  const MIN_ITERATIONS = 600000;
  const MAX_ITERATIONS = 2000000;
  const CONTENT_TYPE = "application/vnd.lab-notes.site+json";
  const state = { files: null, routes: [], currentRoute: "", objectUrls: new Set() };
  const byId = (id) => document.getElementById(id);
  const unlockPanel = byId("unlock-panel");
  const unlockForm = byId("unlock-form");
  const passwordInput = byId("password");
  const unlockButton = byId("unlock-button");
  const unlockStatus = byId("unlock-status");
  const reader = byId("reader");
  const content = byId("content");
  const navigation = byId("navigation");
  const search = byId("search");
  const searchStatus = byId("search-status");
  const sidebar = byId("sidebar");
  const menuButton = byId("menu-button");

  function fromBase64(value) {
    if (typeof value !== "string") throw new Error("invalid release");
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function canonicalHeader(header) {
    const ordered = {};
    Object.keys(header).sort().forEach((key) => { ordered[key] = header[key]; });
    return new TextEncoder().encode(JSON.stringify(ordered));
  }

  function validateEnvelope(envelope) {
    const fields = ["cipher", "ciphertext", "content_type", "iterations", "kdf", "nonce", "salt", "version"];
    if (!envelope || typeof envelope !== "object" || JSON.stringify(Object.keys(envelope).sort()) !== JSON.stringify(fields)) {
      throw new Error("invalid release");
    }
    if (envelope.version !== 1 || envelope.kdf !== "PBKDF2-HMAC-SHA256" || envelope.cipher !== "AES-256-GCM" || envelope.content_type !== CONTENT_TYPE) {
      throw new Error("unsupported release");
    }
    if (!Number.isInteger(envelope.iterations) || envelope.iterations < MIN_ITERATIONS || envelope.iterations > MAX_ITERATIONS) {
      throw new Error("invalid release");
    }
    const salt = fromBase64(envelope.salt);
    const nonce = fromBase64(envelope.nonce);
    if (salt.length !== 16 || nonce.length !== 12) throw new Error("invalid release");
    return { salt, nonce };
  }

  async function decryptRelease(password) {
    const response = await fetch("payload.bin", { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
    if (!response.ok) throw new Error("release unavailable");
    const envelope = await response.json();
    const { salt, nonce } = validateEnvelope(envelope);
    const passwordBytes = new TextEncoder().encode(password);
    let material;
    try {
      material = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: envelope.iterations, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const header = { ...envelope };
      delete header.ciphertext;
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: canonicalHeader(header), tagLength: 128 },
        key,
        fromBase64(envelope.ciphertext)
      );
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    } finally {
      passwordBytes.fill(0);
      material = null;
    }
  }

  function normalizeRoute(location) {
    let route = String(location || "").split("#", 1)[0].split("?", 1)[0];
    route = route.replace(/^\/+/, "");
    if (!route || route === "index.html") return "";
    if (route.endsWith("index.html")) route = route.slice(0, -10);
    if (route.endsWith(".html")) route = `${route.slice(0, -5)}/`;
    if (!route.endsWith("/")) route += "/";
    return route;
  }

  function pagePath(route) {
    return route ? `${route}index.html` : "index.html";
  }

  function decodeText(path) {
    const encoded = state.files[path];
    if (!encoded) throw new Error("page unavailable");
    return new TextDecoder("utf-8", { fatal: true }).decode(fromBase64(encoded));
  }

  function decodeEntities(value) {
    const parsed = new DOMParser().parseFromString(String(value), "text/html");
    return parsed.body.textContent || "";
  }

  function resolvePath(reference, route) {
    const base = `https://reader.invalid/${route}`;
    const url = new URL(reference, base);
    return decodeURIComponent(url.pathname.replace(/^\//, ""));
  }

  function mimeType(path) {
    const suffix = path.toLowerCase().split(".").pop();
    return ({ png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml", pdf: "application/pdf", txt: "text/plain" })[suffix] || "application/octet-stream";
  }

  function assetUrl(path) {
    if (!state.files[path]) return null;
    const url = URL.createObjectURL(new Blob([fromBase64(state.files[path])], { type: mimeType(path) }));
    state.objectUrls.add(url);
    return url;
  }

  function sanitizeArticle(article, route) {
    article.querySelectorAll("script, style, iframe, frame, object, embed, form, meta, link").forEach((element) => element.remove());
    article.querySelectorAll("*").forEach((element) => {
      for (const attribute of [...element.attributes]) {
        if (attribute.name.toLowerCase().startsWith("on") || ["srcdoc", "style"].includes(attribute.name.toLowerCase())) {
          element.removeAttribute(attribute.name);
        }
      }
    });
    article.querySelectorAll("img[src]").forEach((image) => {
      const source = image.getAttribute("src");
      if (!source || /^(data:|blob:)/i.test(source)) return;
      if (/^https?:/i.test(source)) {
        image.remove();
        return;
      }
      try {
        const blob = assetUrl(resolvePath(source, route));
        if (blob) image.setAttribute("src", blob); else image.remove();
      } catch (_) { image.remove(); }
    });
    article.querySelectorAll("a[href]").forEach((link) => {
      const href = link.getAttribute("href");
      if (!href) return;
      if (/^(https?:|mailto:)/i.test(href)) {
        link.setAttribute("rel", "noopener noreferrer");
        link.setAttribute("target", "_blank");
        return;
      }
      if (/^(javascript:|data:|file:)/i.test(href)) {
        link.removeAttribute("href");
        return;
      }
      link.dataset.readerHref = href;
      link.setAttribute("href", "#");
    });
  }

  function renderRoute(route, anchor = "") {
    const normalized = normalizeRoute(route);
    const html = decodeText(pagePath(normalized));
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const source = parsed.querySelector("article.md-content__inner") || parsed.querySelector("main") || parsed.body;
    const article = source.cloneNode(true);
    sanitizeArticle(article, normalized);
    content.replaceChildren(...article.childNodes);
    state.currentRoute = normalized;
    navigation.querySelectorAll("a").forEach((link) => {
      if (link.dataset.route === normalized) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    sidebar.classList.remove("open");
    menuButton.setAttribute("aria-expanded", "false");
    content.focus({ preventScroll: true });
    if (anchor) document.getElementById(anchor)?.scrollIntoView(); else window.scrollTo(0, 0);
  }

  function buildRoutes() {
    const raw = JSON.parse(decodeText("search/search_index.json"));
    const unique = new Map();
    for (const documentEntry of raw.docs || []) {
      const route = normalizeRoute(documentEntry.location);
      if (!unique.has(route)) {
        unique.set(route, { route, title: decodeEntities(documentEntry.title || "Page"), text: decodeEntities(documentEntry.text || "") });
      } else {
        unique.get(route).text += ` ${decodeEntities(documentEntry.text || "")}`;
      }
    }
    state.routes = [...unique.values()].filter((entry) => state.files[pagePath(entry.route)]);
    if (!state.routes.some((entry) => entry.route === "")) throw new Error("release has no start page");
  }

  function renderNavigation(routes) {
    const list = document.createElement("ul");
    routes.forEach((entry) => {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = "#";
      link.dataset.route = entry.route;
      link.textContent = entry.title;
      link.addEventListener("click", (event) => { event.preventDefault(); renderRoute(entry.route); });
      item.append(link);
      list.append(item);
    });
    navigation.replaceChildren(list);
  }

  function applySearch() {
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const matches = terms.length ? state.routes.filter((entry) => {
      const haystack = `${entry.title} ${entry.text}`.toLocaleLowerCase();
      return terms.every((term) => haystack.includes(term));
    }) : state.routes;
    renderNavigation(matches);
    searchStatus.textContent = `${matches.length} page${matches.length === 1 ? "" : "s"} found`;
  }

  function revokeObjects() {
    state.objectUrls.forEach((url) => URL.revokeObjectURL(url));
    state.objectUrls.clear();
  }

  function lock() {
    revokeObjects();
    state.files = null;
    state.routes = [];
    state.currentRoute = "";
    content.replaceChildren();
    navigation.replaceChildren();
    search.value = "";
    reader.hidden = true;
    unlockPanel.hidden = false;
    unlockStatus.textContent = "";
    passwordInput.value = "";
    passwordInput.focus();
  }

  unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    unlockStatus.textContent = "Unlocking…";
    unlockButton.disabled = true;
    const password = passwordInput.value;
    try {
      const payload = await decryptRelease(password);
      if (!payload || payload.schema !== 1 || !payload.files || typeof payload.files !== "object") throw new Error("invalid release");
      state.files = payload.files;
      buildRoutes();
      renderNavigation(state.routes);
      passwordInput.value = "";
      unlockPanel.hidden = true;
      reader.hidden = false;
      renderRoute("");
    } catch (_) {
      state.files = null;
      passwordInput.value = "";
      unlockStatus.textContent = "Unable to unlock. Check the password or try again later.";
      passwordInput.focus();
    } finally {
      unlockButton.disabled = false;
    }
  });

  content.addEventListener("click", (event) => {
    const link = event.target.closest("a[data-reader-href]");
    if (!link) return;
    event.preventDefault();
    const href = link.dataset.readerHref;
    if (href.startsWith("#")) {
      renderRoute(state.currentRoute, href.slice(1));
      return;
    }
    try {
      const resolved = resolvePath(href, state.currentRoute);
      const anchor = href.includes("#") ? href.split("#").pop() : "";
      const route = normalizeRoute(resolved);
      if (state.files[pagePath(route)]) renderRoute(route, anchor);
      else {
        const blob = assetUrl(resolved.split("#", 1)[0]);
        if (blob) window.open(blob, "_blank", "noopener,noreferrer");
      }
    } catch (_) { /* Fail closed for malformed links. */ }
  });
  search.addEventListener("input", applySearch);
  byId("lock-button").addEventListener("click", lock);
  menuButton.addEventListener("click", () => {
    const open = !sidebar.classList.contains("open");
    sidebar.classList.toggle("open", open);
    menuButton.setAttribute("aria-expanded", String(open));
  });
  addEventListener("pagehide", revokeObjects);
  addEventListener("beforeunload", revokeObjects);
})();
