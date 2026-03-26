/**
 * VisionGuard — Content Script
 * Injects a warning banner on high-risk sites.
 */

(() => {
  let bannerVisible = false;

  // ── DOM Scanning Logic ────────────────────────────────────────────────
  function scanDOM() {
    const issues = [];

    // 1. Detect Potential XSS Payloads
    const scripts = document.querySelectorAll("script");
    for (const s of scripts) {
      const content = s.textContent || "";
      if (/alert\(["']?XSS["']?\)/i.test(content) || /<script>alert\(1\)<\/script>/i.test(content)) {
        issues.push({
          type: "vulnerability",
          severity: "high",
          title: "Potential XSS Script Detected",
          detail: "A script block containing common XSS test payloads was found.",
        });
        break; 
      }
    }

    // 2. Detect Tracking Scripts
    const trackers = [
      "google-analytics.com",
      "googletagmanager.com",
      "facebook.net",
      "doubleclick.net",
      "hotjar.com",
    ];
    const externalScripts = document.querySelectorAll("script[src]");
    let trackerCount = 0;
    for (const s of externalScripts) {
      if (trackers.some(t => s.src.includes(t))) {
        trackerCount++;
      }
    }
    if (trackerCount > 0) {
      issues.push({
        type: "privacy",
        severity: "low",
        title: "Tracking Scripts Detected",
        detail: `${trackerCount} known tracking or analytics scripts were identified.`,
      });
    }

    // 3. Detect Fingerprinting Heuristics
    // (Extremely basic: check if canvas is used, though it has many legit uses)
    const hasCanvas = document.querySelectorAll("canvas").length > 0;
    if (hasCanvas && trackerCount > 2) {
      issues.push({
        type: "privacy",
        severity: "medium",
        title: "Potential Fingerprinting",
        detail: "Combination of multiple trackers and canvas usage may indicate fingerprinting.",
      });
    }

    return issues;
  }

  // ── Message Handling ──────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "showBanner" && !bannerVisible) {
      bannerVisible = true;
      injectBanner(message.score, message.issueCount);
    } else if (message.action === "scanDOM") {
      const issues = scanDOM();
      sendResponse({ issues });
    }
  });

  // ── Banner Injection ──────────────────────────────────────────────────
  function injectBanner(score, issueCount) {
    if (document.getElementById("visionguard-banner")) return;

    const banner = document.createElement("div");
    banner.id = "visionguard-banner";
    // ... styles as before ...
    Object.assign(banner.style, {
      position: "fixed", top: "0", left: "0", width: "100%", zIndex: "2147483647",
      background: "linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%)",
      color: "#fff", fontFamily: "'Segoe UI', Roboto, sans-serif", fontSize: "14px",
      padding: "12px 20px", display: "flex", alignItems: "center", justifyContent: "space-between",
      boxShadow: "0 2px 8px rgba(0,0,0,0.3)", animation: "visionguard-slide-in 0.3s ease-out",
    });

    const style = document.createElement("style");
    style.textContent = `
      @keyframes visionguard-slide-in { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
      @keyframes visionguard-slide-out { from { transform: translateY(0); opacity: 1; } to { transform: translateY(-100%); opacity: 0; } }
    `;
    document.head.appendChild(style);

    const msg = document.createElement("span");
    msg.innerHTML = `⚠️ <strong>VisionGuard Warning</strong> — Score: <strong>${score}/100</strong> | <strong>${issueCount}</strong> issue${issueCount !== 1 ? "s" : ""}.`;
    banner.appendChild(msg);

    const btn = document.createElement("button");
    btn.textContent = "✕ Dismiss";
    Object.assign(btn.style, {
      background: "rgba(255,255,255,0.2)", border: "1px solid rgba(255,255,255,0.4)",
      color: "#fff", padding: "4px 12px", borderRadius: "4px", cursor: "pointer",
      fontSize: "13px", marginLeft: "16px", flexShrink: "0",
    });
    btn.addEventListener("click", () => {
      banner.style.animation = "visionguard-slide-out 0.25s ease-in forwards";
      setTimeout(() => banner.remove(), 260);
    });
    banner.appendChild(btn);
    document.body.prepend(banner);
  }
})();
