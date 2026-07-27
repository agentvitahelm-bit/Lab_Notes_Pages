"use strict";

(() => {
  if (window.top !== window.self) {
    document.body.replaceChildren();
    return;
  }
  const MIN_ITERATIONS = 600000;
  const MAX_ITERATIONS = 2000000;
  const CONTENT_TYPE = "application/vnd.lab-notes.site+json";
  const REMEMBERED_UNLOCK_KEY = "lab-notes-remembered-unlock-v1";
  const NAVIGATION_STATE_KEY = "lab-notes-navigation-state-v1";
  const state = { files: null, routes: [], navigation: null, currentRoute: "", navigationRelease: "", objectUrls: new Set() };
  const byId = (id) => document.getElementById(id);
  const unlockPanel = byId("unlock-panel");
  const unlockForm = byId("unlock-form");
  const passwordInput = byId("password");
  const unlockButton = byId("unlock-button");
  const unlockStatus = byId("unlock-status");
  const rememberInput = byId("remember-unlock");
  const reader = byId("reader");
  const content = byId("content");
  const skipLink = document.querySelector(".skip-link");
  const navigation = byId("navigation");
  const search = byId("search");
  const searchStatus = byId("search-status");
  const sidebar = byId("sidebar");
  const menuButton = byId("menu-button");
  const closeMenuButton = byId("close-menu-button");
  const readerHeader = document.querySelector(".reader-header");
  const forgetButton = byId("forget-button");
  const readerStatus = byId("reader-status");
  const mobileNavigation = matchMedia("(max-width: 46rem)");

  function setMenuOpen(open, returnFocus = false) {
    const mobileOpen = mobileNavigation.matches && open;
    const modalMobileOpen = mobileNavigation.matches && mobileOpen;
    sidebar.classList.toggle("open", mobileOpen);
    menuButton.setAttribute("aria-expanded", String(mobileOpen));
    sidebar.inert = mobileNavigation.matches && !mobileOpen;
    sidebar.setAttribute("aria-hidden", String(mobileNavigation.matches && !mobileOpen));
    readerHeader.inert = modalMobileOpen;
    content.inert = modalMobileOpen;
    if (modalMobileOpen) search.focus();
    else if (returnFocus) menuButton.focus();
  }

  function mobileMenuFocusableElements() {
    return [...sidebar.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
    )].filter((element) => {
      const closedDetails = element.closest("details:not([open])");
      const isClosedDetailsSummary = closedDetails
        && element.tagName === "SUMMARY"
        && element.parentElement === closedDetails;
      return element.tabIndex >= 0
        && !element.hidden
        && element.getClientRects().length > 0
        && (!closedDetails || isClosedDetailsSummary);
    });
  }

  function syncMenuForViewport() {
    setMenuOpen(!mobileNavigation.matches);
  }

  function fromBase64(value) {
    if (typeof value !== "string") throw new Error("invalid release");
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function toBase64(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary);
  }

  function canonicalHeader(header) {
    const ordered = {};
    Object.keys(header).sort().forEach((key) => { ordered[key] = header[key]; });
    return new TextEncoder().encode(JSON.stringify(ordered));
  }

  async function envelopeFingerprint(envelope) {
    return toBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalHeader(envelope))));
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

  async function fetchEnvelope() {
    const response = await fetch("payload.bin", { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
    if (!response.ok) throw new Error("release unavailable");
    const envelope = await response.json();
    validateEnvelope(envelope);
    return envelope;
  }

  async function decryptWithKey(envelope, key) {
    const { nonce } = validateEnvelope(envelope);
    const header = { ...envelope };
    delete header.ciphertext;
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: canonicalHeader(header), tagLength: 128 },
      key,
      fromBase64(envelope.ciphertext)
    );
    const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    if (!payload || payload.schema !== 1 || !payload.files || typeof payload.files !== "object") {
      throw new Error("invalid release");
    }
    return payload;
  }

  function clearRememberedUnlock() {
    try { localStorage.removeItem(REMEMBERED_UNLOCK_KEY); } catch (_) { /* Storage may be blocked. */ }
    forgetButton.hidden = true;
  }

  function readNavigationState(sectionCount) {
    let raw;
    try { raw = localStorage.getItem(NAVIGATION_STATE_KEY); } catch (_) { return new Set([0]); }
    if (!raw) return new Set([0]);
    try {
      const record = JSON.parse(raw);
      if (
        !record ||
        typeof record !== "object" ||
        JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(["open", "release", "version"]) ||
        record.version !== 1 ||
        record.release !== state.navigationRelease ||
        !Array.isArray(record.open) ||
        record.open.some((index) => !Number.isInteger(index) || index < 0 || index >= sectionCount) ||
        new Set(record.open).size !== record.open.length
      ) {
        throw new Error("invalid navigation state");
      }
      return new Set(record.open);
    } catch (_) {
      try { localStorage.removeItem(NAVIGATION_STATE_KEY); } catch (_) { /* Storage may be blocked. */ }
      return new Set([0]);
    }
  }

  function saveNavigationState() {
    const groups = [...navigation.querySelectorAll("details.navigation-section")];
    if (!groups.length) return;
    const open = groups.flatMap((group, index) => group.open ? [index] : []);
    if (!state.navigationRelease) return;
    try {
      localStorage.setItem(
        NAVIGATION_STATE_KEY,
        JSON.stringify({ version: 1, release: state.navigationRelease, open })
      );
    } catch (_) { /* Storage may be blocked. */ }
  }

  function readRememberedUnlock() {
    let raw;
    try { raw = localStorage.getItem(REMEMBERED_UNLOCK_KEY); } catch (_) { return null; }
    if (!raw) return null;
    const record = JSON.parse(raw);
    const fields = ["iterations", "key", "release", "salt", "version"];
    if (!record || typeof record !== "object" || JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(fields)) {
      throw new Error("invalid saved unlock");
    }
    if (record.version !== 1 || !Number.isInteger(record.iterations) || record.iterations < MIN_ITERATIONS || record.iterations > MAX_ITERATIONS) {
      throw new Error("invalid saved unlock");
    }
    if (fromBase64(record.salt).length !== 16 || fromBase64(record.key).length !== 32 || fromBase64(record.release).length !== 32) {
      throw new Error("invalid saved unlock");
    }
    return record;
  }

  function saveRememberedUnlock(record) {
    try {
      localStorage.setItem(REMEMBERED_UNLOCK_KEY, JSON.stringify(record));
      forgetButton.hidden = false;
      return true;
    } catch (_) {
      clearRememberedUnlock();
      return false;
    }
  }

  async function decryptRelease(password, shouldRemember) {
    const envelope = await fetchEnvelope();
    const { salt } = validateEnvelope(envelope);
    const passwordBytes = new TextEncoder().encode(password);
    let material;
    try {
      material = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: envelope.iterations, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        shouldRemember,
        ["decrypt"]
      );
      const payload = await decryptWithKey(envelope, key);
      const release = await envelopeFingerprint(envelope);
      let remembered = null;
      if (shouldRemember) {
        const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
        try {
          remembered = {
            version: 1,
            salt: envelope.salt,
            iterations: envelope.iterations,
            release,
            key: toBase64(rawKey)
          };
        } finally {
          rawKey.fill(0);
        }
      }
      return { payload, remembered, release };
    } finally {
      passwordBytes.fill(0);
      material = null;
    }
  }

  async function decryptRememberedRelease(record) {
    const envelope = await fetchEnvelope();
    const release = await envelopeFingerprint(envelope);
    if (
      record.salt !== envelope.salt ||
      record.iterations !== envelope.iterations ||
      record.release !== release
    ) {
      throw new Error("saved unlock is for another release");
    }
    const rawKey = fromBase64(record.key);
    let key;
    try {
      key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    } finally {
      rawKey.fill(0);
    }
    return { payload: await decryptWithKey(envelope, key), release };
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
    // MkDocs preserves links relative to the source Markdown file, while reader
    // routes use directory-style URLs. Resolve against a synthetic file path so
    // ../../source-assets and sibling assets keep their authored depth.
    const routeFile = route ? `${route.replace(/\/$/, "")}.html` : "index.html";
    const base = `https://reader.invalid/${routeFile}`;
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

  function initializeInventoryTable() {
    const table = content.querySelector("[data-inventory-table]");
    const controls = content.querySelector("[data-inventory-controls]");
    if (!table || !controls) return;
    const rows = [...table.querySelectorAll("[data-inventory-row]")];
    const textInput = controls.querySelector("[data-inventory-search]");
    const category = controls.querySelector("[data-inventory-category]");
    const holder = controls.querySelector("[data-inventory-holder]");
    const availability = controls.querySelector("[data-inventory-availability]");
    const completeness = controls.querySelector("[data-inventory-completeness]");
    const status = controls.querySelector("[data-inventory-status]");
    if (!textInput || !category || !holder || !availability || !completeness || !status) return;

    const update = () => {
      const terms = textInput.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
      let visible = 0;
      rows.forEach((row) => {
        const matchesText = terms.every((term) => (row.dataset.search || "").includes(term));
        const matchesCategory = !category.value || row.dataset.category === category.value;
        const matchesHolder = !holder.value || row.dataset.holder === holder.value;
        const matchesAvailability = !availability.value || row.dataset.availability === availability.value;
        const hasGaps = row.dataset.gaps === "true";
        const matchesCompleteness = !completeness.value
          || (completeness.value === "gaps" && hasGaps)
          || (completeness.value === "complete" && !hasGaps);
        const show = matchesText && matchesCategory && matchesHolder && matchesAvailability && matchesCompleteness;
        row.hidden = !show;
        if (show) visible += 1;
      });
      status.textContent = `Showing ${visible} of ${rows.length} rows`;
    };
    textInput.addEventListener("input", update);
    [category, holder, availability, completeness].forEach((control) => control.addEventListener("change", update));
    update();
  }

  function renderRoute(route, anchor = "") {
    const normalized = normalizeRoute(route);
    const html = decodeText(pagePath(normalized));
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const source = parsed.querySelector("article.md-content__inner") || parsed.querySelector("main") || parsed.body;
    const article = source.cloneNode(true);
    sanitizeArticle(article, normalized);
    content.replaceChildren(...article.childNodes);
    initializeInventoryTable();
    state.currentRoute = normalized;
    navigation.querySelectorAll("a").forEach((link) => {
      if (link.dataset.route === normalized) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const currentNavigationLink = [...navigation.querySelectorAll("a")].find(
      (link) => link.dataset.route === normalized
    );
    const currentGroup = currentNavigationLink && currentNavigationLink.closest("details.navigation-section");
    if (currentGroup) {
      currentGroup.open = true;
      saveNavigationState();
    }
    setMenuOpen(false);
    content.focus({ preventScroll: true });
    if (anchor) {
      const target = document.getElementById(anchor);
      const disclosure = target && target.closest("details");
      if (disclosure) disclosure.open = true;
      target?.scrollIntoView();
    } else window.scrollTo(0, 0);
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

  function loadNavigation() {
    const raw = JSON.parse(decodeText("reader-navigation.json"));
    if (!raw || raw.schema !== 2 || !Array.isArray(raw.utilities) || !Array.isArray(raw.sections) || !Array.isArray(raw.search_records) || raw.sections.length < 5 || raw.sections.length > 7) {
      throw new Error("release has invalid navigation");
    }
    const knownRoutes = new Set(state.routes.map((entry) => entry.route));
    const seen = new Set();
    const entries = [...raw.utilities, ...raw.sections.flatMap((section) => {
      if (!section || typeof section.title !== "string" || !Array.isArray(section.items)) throw new Error("release has invalid navigation");
      return section.items;
    })];
    entries.forEach((entry) => {
      if (!entry || typeof entry.title !== "string" || !entry.title.trim() || typeof entry.route !== "string") throw new Error("release has invalid navigation");
      const route = normalizeRoute(entry.route);
      if (!knownRoutes.has(route) || seen.has(route)) throw new Error("release has invalid navigation");
      entry.route = route;
      seen.add(route);
    });
    const searchSeen = new Set();
    raw.search_records.forEach((entry) => {
      if (!entry || typeof entry.title !== "string" || typeof entry.text !== "string" || typeof entry.route !== "string" || !["reviewed-guidance", "draft-guidance"].includes(entry.status)) {
        throw new Error("release has invalid search metadata");
      }
      entry.route = normalizeRoute(entry.route);
      entry.anchor = String(entry.anchor || "");
      const identity = `${entry.status}\u0000${entry.route}\u0000${entry.anchor}`;
      if (!knownRoutes.has(entry.route) || searchSeen.has(identity)) throw new Error("release has invalid search metadata");
      searchSeen.add(identity);
    });
    state.navigation = raw;
  }

  function navigationLink(entry, searchResult = false) {
    const link = document.createElement("a");
    link.href = "#";
    link.dataset.route = entry.route;
    if (entry.anchor) link.dataset.anchor = entry.anchor;
    if (searchResult) {
      const title = document.createElement("span");
      title.className = "search-result-title";
      title.textContent = entry.title;
      const badge = document.createElement("span");
      badge.className = `status-badge ${entry.status}`;
      badge.textContent = entry.status === "reviewed-guidance" ? "Reviewed guidance" : "Controlled draft";
      const context = document.createElement("small");
      context.textContent = entry.context || "";
      link.append(title, badge, context);
    } else {
      link.textContent = entry.title;
    }
    link.addEventListener("click", (event) => {
      event.preventDefault();
      if (searchResult) {
        search.value = "";
        state.currentRoute = entry.route;
        renderNavigation();
        searchStatus.textContent = `${state.navigation.sections.length} main sections`;
      }
      renderRoute(entry.route, entry.anchor || "");
    });
    return link;
  }

  function renderNavigation(routes = null) {
    if (routes) {
      const list = document.createElement("ul");
      list.className = "search-results";
      routes.forEach((entry) => {
        const item = document.createElement("li");
        item.append(navigationLink(entry, true));
        list.append(item);
      });
      navigation.replaceChildren(list);
      return;
    }

    const fragment = document.createDocumentFragment();
    const utilityList = document.createElement("ul");
    utilityList.className = "navigation-utilities";
    state.navigation.utilities.forEach((entry) => {
      const item = document.createElement("li");
      item.append(navigationLink(entry));
      utilityList.append(item);
    });
    fragment.append(utilityList);

    const openSections = readNavigationState(state.navigation.sections.length);
    state.navigation.sections.forEach((section, index) => {
      const group = document.createElement("details");
      group.className = "navigation-section";
      group.dataset.section = section.slug;
      group.open = openSections.has(index);
      group.addEventListener("toggle", saveNavigationState);
      const summary = document.createElement("summary");
      summary.textContent = section.title;
      group.append(summary);
      const list = document.createElement("ul");
      section.items.forEach((entry) => {
        const item = document.createElement("li");
        item.append(navigationLink(entry));
        list.append(item);
      });
      group.append(list);
      fragment.append(group);
    });
    navigation.replaceChildren(fragment);
    if (state.currentRoute) {
      const currentLink = [...navigation.querySelectorAll("a")].find(
        (link) => link.dataset.route === state.currentRoute
      );
      if (currentLink) {
        currentLink.setAttribute("aria-current", "page");
        const currentSection = currentLink.closest("details.navigation-section");
        if (currentSection) {
          currentSection.open = true;
          saveNavigationState();
        }
      }
    }
  }

  function applySearch() {
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const scored = terms.length ? state.navigation.search_records.map((entry, index) => {
      const haystack = `${entry.title} ${entry.context || ""} ${entry.text}`.toLocaleLowerCase();
      return { entry, index, score: terms.filter((term) => haystack.includes(term)).length };
    }) : [];
    let matches = scored.filter(({ score }) => score === terms.length).map(({ entry }) => entry);
    if (!matches.length && terms.length > 1) {
      matches = scored
        .filter(({ score }) => score >= terms.length - 1)
        .sort((left, right) => right.score - left.score || left.index - right.index)
        .map(({ entry }) => entry);
    }
    renderNavigation(terms.length ? matches : null);
    searchStatus.textContent = terms.length
      ? `${matches.length} result${matches.length === 1 ? "" : "s"} found`
      : `${state.navigation.sections.length} main sections`;
  }

  function revokeObjects() {
    state.objectUrls.forEach((url) => URL.revokeObjectURL(url));
    state.objectUrls.clear();
  }

  function showReader(payload, release) {
    state.files = payload.files;
    state.navigationRelease = release;
    buildRoutes();
    loadNavigation();
    renderNavigation();
    searchStatus.textContent = `${state.navigation.sections.length} main sections`;
    passwordInput.value = "";
    unlockPanel.hidden = true;
    reader.hidden = false;
    renderRoute("");
  }

  function lock() {
    revokeObjects();
    state.files = null;
    state.routes = [];
    state.navigation = null;
    state.currentRoute = "";
    state.navigationRelease = "";
    content.replaceChildren();
    navigation.replaceChildren();
    search.value = "";
    reader.hidden = true;
    unlockPanel.hidden = false;
    unlockStatus.textContent = "";
    readerStatus.textContent = "";
    passwordInput.value = "";
    rememberInput.checked = !forgetButton.hidden;
    passwordInput.focus();
  }

  unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    unlockStatus.textContent = "Unlocking…";
    unlockButton.disabled = true;
    const password = passwordInput.value;
    const shouldRemember = rememberInput.checked;
    try {
      const { payload, remembered, release } = await decryptRelease(password, shouldRemember);
      if (remembered) {
        const saved = saveRememberedUnlock(remembered);
        readerStatus.textContent = saved
          ? "Unlock remembered on this device until the encrypted site is updated."
          : "Unlocked for this visit; browser storage was unavailable.";
      } else {
        clearRememberedUnlock();
        readerStatus.textContent = "";
      }
      showReader(payload, release);
    } catch (_) {
      state.files = null;
      passwordInput.value = "";
      unlockStatus.textContent = "Unable to unlock. Check the password or try again later.";
      passwordInput.focus();
    } finally {
      unlockButton.disabled = false;
    }
  });

  async function attemptRememberedUnlock() {
    let record;
    try {
      record = readRememberedUnlock();
    } catch (_) {
      clearRememberedUnlock();
      unlockStatus.textContent = "Saved unlock was invalid and has been removed. Enter the password again.";
      return;
    }
    if (!record) return;
    unlockStatus.textContent = "Unlocking with the saved device key…";
    unlockButton.disabled = true;
    try {
      const { payload, release } = await decryptRememberedRelease(record);
      forgetButton.hidden = false;
      readerStatus.textContent = "Unlocked with the saved device key. Use Forget saved unlock to remove it.";
      showReader(payload, release);
    } catch (error) {
      if (error?.message !== "release unavailable") clearRememberedUnlock();
      unlockStatus.textContent = "Saved unlock could not open this release. Enter the password again.";
    } finally {
      unlockButton.disabled = false;
    }
  }

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
  skipLink.addEventListener("click", (event) => {
    if (reader.hidden) return;
    event.preventDefault();
    history.replaceState(null, "", "#content");
    content.focus();
  });
  byId("lock-button").addEventListener("click", lock);
  forgetButton.addEventListener("click", () => {
    clearRememberedUnlock();
    lock();
    rememberInput.checked = false;
    unlockStatus.textContent = "Saved unlock removed from this browser.";
  });
  menuButton.addEventListener("click", () => {
    const open = menuButton.getAttribute("aria-expanded") !== "true";
    setMenuOpen(open, !open);
  });
  closeMenuButton.addEventListener("click", () => setMenuOpen(false, true));
  addEventListener("keydown", (event) => {
    const mobileMenuOpen = mobileNavigation.matches
      && menuButton.getAttribute("aria-expanded") === "true";
    if (event.key === "Escape" && mobileMenuOpen) {
      setMenuOpen(false, true);
    } else if (event.key === "Tab" && mobileMenuOpen) {
      const focusable = mobileMenuFocusableElements();
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!sidebar.contains(document.activeElement)) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  mobileNavigation.addEventListener("change", syncMenuForViewport);
  syncMenuForViewport();
  addEventListener("pagehide", revokeObjects);
  addEventListener("beforeunload", revokeObjects);
  attemptRememberedUnlock();
})();
