/**
 * VisionGuard — Analyzer Utilities
 * Helper functions for scoring and analyzing headers, cookies, and URL risks.
 */

const Analyzer = (() => {
  // ── Security Headers ──────────────────────────────────────────────────
  const REQUIRED_HEADERS = [
    {
      name: "content-security-policy",
      label: "Content-Security-Policy (CSP)",
      weight: 25,
      severity: "high",
      description: "Helps prevent XSS and data injection attacks.",
    },
    {
      name: "strict-transport-security",
      label: "Strict-Transport-Security (HSTS)",
      weight: 25,
      severity: "high",
      description: "Enforces HTTPS connections to the server.",
    },
    {
      name: "x-frame-options",
      label: "X-Frame-Options",
      weight: 15,
      severity: "medium",
      description: "Prevents clickjacking by restricting framing.",
    },
    {
      name: "x-content-type-options",
      label: "X-Content-Type-Options",
      weight: 10,
      severity: "medium",
      description: "Prevents MIME-type sniffing.",
    },
  ];

  // ── Phishing Heuristics ───────────────────────────────────────────────
  const SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "password", "signin", "wallet", "suspend", "unusual", "alert", "expire",
    "locked", "urgent"
  ];

  const SUSPICIOUS_TLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz", ".top", ".club", ".work", ".click"];

  const BLACKLISTED_DOMAINS = [
    "phish-test.com",
    "malware-test.net",
    "example-phishing.org"
  ];

  /**
   * Analyze security headers.
   */
  function analyzeHeaders(headers) {
    let score = 0;
    const issues = [];
    const lowerHeaders = {};
    for (const k in headers) lowerHeaders[k.toLowerCase()] = headers[k];

    for (const hdr of REQUIRED_HEADERS) {
      if (lowerHeaders[hdr.name]) {
        score += hdr.weight;
      } else {
        issues.push({
          type: "header",
          severity: hdr.severity,
          title: `Missing ${hdr.label}`,
          detail: hdr.description,
        });
      }
    }

    return { score, issues, maxScore: 75 };
  }

  /**
   * Check connection protocol and simulated TLS.
   */
  function analyzeProtocol(url) {
    const isHttps = url.startsWith("https://");
    const issues = [];
    let score = isHttps ? 15 : 0;

    if (!isHttps) {
      issues.push({
        type: "protocol",
        severity: "high",
        title: "Insecure Connection (HTTP)",
        detail: "This page is served over plain HTTP. Data can be intercepted.",
      });
    } else {
      // Heuristic for "outdated TLS" simulation if URL has specific markers (for testing)
      if (url.includes("tls10") || url.includes("tls11")) {
        score -= 5;
        issues.push({
          type: "protocol",
          severity: "medium",
          title: "Outdated TLS Version",
          detail: "The site appears to use an outdated TLS version (TLS 1.0/1.1).",
        });
      }
    }

    return { score, issues, maxScore: 15 };
  }

  /**
   * Phishing and malware detection.
   */
  function analyzePhishing(url) {
    const issues = [];
    let deductions = 0;

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();

      // Blacklist check
      if (BLACKLISTED_DOMAINS.some(d => hostname.endsWith(d))) {
        deductions += 10;
        issues.push({
          type: "malware",
          severity: "critical",
          title: "Known Malicious Domain",
          detail: "This site is on a known blacklist for phishing or malware.",
        });
      }

      // Check suspicious TLDs
      for (const tld of SUSPICIOUS_TLDs) {
        if (hostname.endsWith(tld)) {
          deductions += 5;
          issues.push({
            type: "phishing",
            severity: "medium",
            title: `Suspicious TLD (${tld})`,
            detail: "This TLD is commonly used for malicious purposes.",
          });
          break;
        }
      }

      // Check suspicious keywords
      let keywordHits = 0;
      for (const kw of SUSPICIOUS_KEYWORDS) {
        if (fullUrl.includes(kw)) keywordHits++;
      }
      if (keywordHits >= 3) {
        deductions += 5;
        issues.push({
          type: "phishing",
          severity: "medium",
          title: "Multiple Suspicious Keywords",
          detail: `${keywordHits} suspicious keywords found in the URL.`,
        });
      }

      // Open redirect heuristic
      if (parsed.searchParams.has("url") || parsed.searchParams.has("redirect") || parsed.searchParams.has("next")) {
        const target = parsed.searchParams.get("url") || parsed.searchParams.get("redirect") || parsed.searchParams.get("next");
        if (target && (target.startsWith("http") || target.startsWith("//"))) {
          deductions += 3;
          issues.push({
            type: "vulnerability",
            severity: "low",
            title: "Potential Open Redirect",
            detail: "The URL contains a redirection parameter which could be abused.",
          });
        }
      }

      // IP-based URL
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        deductions += 5;
        issues.push({
          type: "phishing",
          severity: "high",
          title: "IP-Based URL",
          detail: "The site uses a raw IP address instead of a domain name.",
        });
      }
    } catch (_) {}

    return { score: Math.max(0, 10 - deductions), issues, maxScore: 10 };
  }

  /**
   * Analyze cookies for security flags.
   */
  function analyzeCookies(cookies, currentDomain) {
    const issues = [];
    const total = cookies.length;
    let thirdParty = 0;
    let insecureCount = 0;

    for (const c of cookies) {
      const cookieDomain = c.domain.replace(/^\./, "");
      if (!currentDomain.endsWith(cookieDomain) && !cookieDomain.endsWith(currentDomain)) {
        thirdParty++;
      }
      if (!c.secure || !c.httpOnly) {
        insecureCount++;
      }
    }

    let deductions = 0;
    if (thirdParty > 10) deductions += 5;
    if (insecureCount > 0) {
      deductions += Math.min(insecureCount, 5);
      issues.push({
        type: "cookies",
        severity: "medium",
        title: "Insecure Cookie Flags",
        detail: `${insecureCount} cookies are missing Secure or HttpOnly flags.`,
      });
    }

    return {
      total,
      thirdParty,
      score: Math.max(0, 10 - deductions),
      issues,
      maxScore: 10,
    };
  }

  /**
   * Build combined report.
   */
  function buildReport(data) {
    const headerResult = analyzeHeaders(data.headers || {});
    const protocolResult = analyzeProtocol(data.url);
    const phishingResult = analyzePhishing(data.url);
    const cookieResult = analyzeCookies(data.cookies || [], data.domain || "");
    const domIssues = data.domIssues || [];

    const totalScore = headerResult.score + protocolResult.score + phishingResult.score + cookieResult.score;
    const maxPossible = 75 + 15 + 10 + 10;
    let normalizedScore = Math.round((totalScore / maxPossible) * 100);

    // Apply deductions for DOM issues
    normalizedScore = Math.max(0, normalizedScore - domIssues.length * 10);

    const allIssues = [
      ...protocolResult.issues,
      ...headerResult.issues,
      ...phishingResult.issues,
      ...cookieResult.issues,
      ...domIssues
    ];

    let grade = "safe";
    if (normalizedScore < 50) grade = "danger";
    else if (normalizedScore < 80) grade = "warning";

    return {
      url: data.url,
      domain: data.domain,
      score: normalizedScore,
      grade,
      issues: allIssues,
      cookies: { total: cookieResult.total, thirdParty: cookieResult.thirdParty },
      timestamp: new Date().toISOString(),
    };
  }

  return {
    analyzeHeaders,
    analyzeProtocol,
    analyzePhishing,
    analyzeCookies,
    buildReport,
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.Analyzer = Analyzer;
}
