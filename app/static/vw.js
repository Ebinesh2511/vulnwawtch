// Shared front-end helpers. Loaded before Alpine.

// ---------- time (shown in the viewer's own timezone) ----------
window.vw = {
  local(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString(undefined, { day: "numeric", month: "short", hour: "numeric", minute: "2-digit", timeZoneName: "short" });
  },
  ago(iso) {
    if (!iso) return "";
    const s = Math.round((Date.now() - new Date(iso)) / 1000);
    if (isNaN(s)) return "";
    if (s < 45) return "just now";
    const m = Math.round(s / 60); if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60); if (h < 24) return `${h} h ago`;
    const d = Math.round(h / 24); return d < 30 ? `${d} d ago` : vw.local(iso).split(",")[0];
  },
  duration(a, b) {
    const s = Math.max(0, Math.round(((b ? new Date(b) : Date.now()) - new Date(a)) / 1000));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60); if (m < 60) return `${m}m ${s % 60}s`;
    return `${Math.floor(m / 60)}h ${m % 60}m`;
  },
  plural(n, one, many) { return `${n} ${n === 1 ? one : (many || one + "s")}`; },
  async post(url, body) {
    const r = await fetch(url, { method: "POST", body: body ? new URLSearchParams(body) : undefined });
    return r.json().catch(() => ({}));
  },
  toast(message, opts = {}) { window.dispatchEvent(new CustomEvent("vw-toast", { detail: { message, ...opts } })); },
};

// ---------- theme ----------
window.vwTheme = {
  get() { try { return localStorage.getItem("vw-theme") || "system"; } catch (e) { return "system"; } },
  apply(t) {
    const dark = t === "dark" || (t === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.dataset.theme = t;
  },
  next() {
    const order = ["system", "light", "dark"];
    const t = order[(order.indexOf(this.get()) + 1) % 3];
    try { localStorage.setItem("vw-theme", t); } catch (e) {}
    this.apply(t);
    return t;
  },
};
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => vwTheme.apply(vwTheme.get()));

document.addEventListener("alpine:init", () => {
  // ---------- toasts ----------
  Alpine.data("toasts", () => ({
    items: [], n: 0,
    add(d) {
      const id = ++this.n;
      this.items.push({ id, kind: "info", ...d });
      setTimeout(() => this.remove(id), d.timeout || 4000);
    },
    remove(id) { this.items = this.items.filter(t => t.id !== id); },
  }));

  // ---------- job status: one shared poller (header + mobile menu read it); announces finish ----------
  Alpine.store("job", {
    job: null, line: "", wasRunning: false,
    async poll() {
      try {
        const s = await (await fetch("/api/job")).json();
        if (this.wasRunning && !s.job) {
          const ok = s.last && s.last.ok;
          vw.toast(ok ? `Finished: ${s.last.job}` : `Run ended with errors: ${s.last ? s.last.job : ""}`, { kind: ok ? "ok" : "error" });
          window.dispatchEvent(new Event("vw-refresh"));
        }
        this.wasRunning = !!s.job; this.job = s.job; this.line = s.line;
      } catch (e) {}
    },
    init() { this.poll(); setInterval(() => this.poll(), 3000); },
    async run() {
      const r = await vw.post("/api/run/pipeline");
      vw.toast(r.started ? "Full check started. You can keep working." : "A job is already running.", { kind: r.started ? "ok" : "info" });
      this.poll();
    },
  });

  // pages build their own object as { ...vwFinding(), ...their own getters }
  window.vwFinding = () => ({
    guides: {}, busy: {},
    FIX: {
      ready:     { label: "Fix ready (dry run)", pill: "pill-green", icon: "bot" },
      pr_opened: { label: "PR opened", pill: "pill-green", icon: "pr" },
      escalated: { label: "Needs a developer", pill: "pill-amber", icon: "alert" },
      failed:    { label: "Fix failed", pill: "pill-red", icon: "xcircle" },
    },
    KIND: { declared: "Declared", locked: "Lockfile", pulled_in_by: "Pulled in by", used: "Used here" },
    PRIO: {
      0: { bar: "bg-red-600", text: "text-red-700 dark:text-red-300", dot: "bg-red-600", ring: "ring-red-500" },
      1: { bar: "bg-orange-500", text: "text-orange-800 dark:text-orange-300", dot: "bg-orange-500", ring: "ring-orange-500" },
      2: { bar: "bg-amber-400", text: "text-amber-800 dark:text-amber-300", dot: "bg-amber-400", ring: "ring-amber-500" },
      3: { bar: "bg-slate-400", text: "text-slate-700 dark:text-slate-300", dot: "bg-slate-400", ring: "ring-slate-500" },
    },
    VERDICT: { yes: ["Affected", "pill-red"], maybe: ["Possibly affected", "pill-amber"], no: ["Not reachable", "pill-green"] },
    STRATEGY: { patch_upgrade: "Patch upgrade", minor_upgrade: "Minor upgrade", major_upgrade: "Major upgrade",
                override_transitive: "Override pulled-in version", config_mitigation: "Config change", replace_library: "Replace library",
                remove_unused: "Remove unused library", no_fix_available: "No fix yet" },
    researchNotes: {},
    async loadResearch(f) {
      if (!this.researchNotes[f.id]) this.researchNotes[f.id] = (await (await fetch(`/api/findings/${f.id}/research`)).json()).html || "<p>No notes.</p>";
    },
    async reResearch(f) {
      const r = await vw.post(`/api/findings/${f.id}/research`);
      vw.toast(r.started ? `Researching ${f.package} on the web (about a minute)…` : "Another job is running; try again in a moment.", { kind: r.started ? "ok" : "info" });
      if (r.started) delete this.researchNotes[f.id];
    },
    sevClass(s) { return "sev-" + (s || "UNKNOWN"); },
    files(fx) { try { return JSON.parse(fx.files || "[]"); } catch (e) { return []; } },
    async loadGuide(f) {
      if (f.has_guide && !this.guides[f.id]) this.guides[f.id] = (await (await fetch(`/api/findings/${f.id}/guide`)).json()).html;
    },
    async setStatus(f, status, label) {
      const prev = f.status;
      await vw.post(`/api/findings/${f.id}/status`, { status });
      vw.toast(`${f.package} in ${f.repo}: ${label}`, {
        kind: "ok", undo: async () => { await vw.post(`/api/findings/${f.id}/status`, { status: prev }); window.dispatchEvent(new Event("vw-refresh")); },
      });
      window.dispatchEvent(new Event("vw-refresh"));
    },
    async fixNow(f) {
      this.busy[f.id] = true;
      const r = await vw.post(`/api/findings/${f.id}/fix`);
      vw.toast(r.started ? `Preparing a fix for ${f.package}…` : "Another job is running; try again in a moment.", { kind: r.started ? "ok" : "info" });
      setTimeout(() => { this.busy[f.id] = false; }, 4000);
    },
    async analyze(f) {
      const r = await vw.post(`/api/findings/${f.id}/analyze`);
      vw.toast(r.started ? `AI review started for ${f.package}` : "Another job is running; try again in a moment.", { kind: r.started ? "ok" : "info" });
    },
  });
});

vwTheme.apply(vwTheme.get());
