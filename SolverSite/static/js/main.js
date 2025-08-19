// theme
(function(){
    const KEY = "theme";
    const html = document.documentElement;
    const btn = () => document.getElementById("themeToggle");
  
    function applyTheme(mode){
      if(mode === "auto"){
        const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        html.setAttribute("data-theme", prefersDark ? "dark" : "light");
      }else{
        html.setAttribute("data-theme", mode);
      }
    }
    function current(){
      return localStorage.getItem(KEY) || "auto";
    }
    function toggle(){
      const cur = current();
      const next = cur === "dark" ? "light" : (cur === "light" ? "auto" : "dark");
      localStorage.setItem(KEY, next);
      applyTheme(next);
      if(btn()) btn().textContent = (next === "dark" ? "🌙" : (next === "light" ? "☀️" : "🌗"));
    }
    document.addEventListener("DOMContentLoaded", () => {
      applyTheme(current());
      if(btn()){
        const cur = current();
        btn().textContent = (cur === "dark" ? "🌙" : (cur === "light" ? "☀️" : "🌗"));
        btn().addEventListener("click", toggle);
      }
      // React to system changes if user chose auto
      if(current() === "auto" && window.matchMedia){
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme("auto"));
      }
    });
  })();
  
  // Copy / Expand
  document.addEventListener("click", (e) => {
    const t = e.target;
    if (t.matches("[data-copy]")) {
      const sel = t.getAttribute("data-copy");
      const el = document.querySelector(sel);
      if (el) {
        const text = el.textContent || "";
        navigator.clipboard.writeText(text).then(() => {
          const prev = t.textContent;
          t.textContent = "Copied";
          setTimeout(() => (t.textContent = prev), 1200);
        });
      }
    }
    if (t.matches("[data-expand]")) {
      const sel = t.getAttribute("data-expand");
      const el = document.querySelector(sel);
      const full = t.getAttribute("data-full") || "";
      if (el && full) {
        el.textContent = JSON.parse(full);
        const prev = t.textContent;
        t.textContent = "Expanded";
        setTimeout(() => (t.textContent = prev), 1200);
      }
    }
  });
  