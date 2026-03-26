document.addEventListener("DOMContentLoaded", async () => {
  const siteNameEl     = document.getElementById("site-name");
  const siteUrlEl      = document.getElementById("site-url");
  const ringFgEl       = document.getElementById("ring-fg");
  const scoreValueEl   = document.getElementById("score-value");
  const scoreLabelEl   = document.getElementById("score-label");
  const scoreSection   = document.getElementById("score-section");
  const issuesListEl   = document.getElementById("issues-list");
  const cookiesTotalEl = document.getElementById("cookies-total");
  const cookiesThirdEl = document.getElementById("cookies-third");
  
  const downloadTxtBtn  = document.getElementById("download-btn");
  const downloadJsonBtn = document.getElementById("download-json");
  const downloadCsvBtn  = document.getElementById("download-csv");

  let currentTabId = null;

  // 1. Initial Load
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    siteNameEl.textContent = "No scannable page";
    siteUrlEl.textContent  = tab?.url || "";
    scoreLabelEl.textContent = "Navigate to a website to scan.";
    return;
  }

  currentTabId = tab.id;
  try {
    siteNameEl.textContent = new URL(tab.url).hostname;
  } catch {
    siteNameEl.textContent = tab.title || "Unknown";
  }
  siteUrlEl.textContent = tab.url;

  const fetchAndRender = () => {
    chrome.runtime.sendMessage({ action: "getReport", tabId: currentTabId }, (response) => {
      if (response && response.report) renderReport(response.report);
    });
  };

  fetchAndRender();

  // 2. Real-time Updates via Storage Listener
  chrome.storage.onChanged.addListener((changes) => {
    if (changes[`report_${currentTabId}`]) {
      renderReport(changes[`report_${currentTabId}`].newValue);
    }
  });

  // 3. Render function
  function renderReport(report) {
    const circumference = 326.73;
    ringFgEl.style.strokeDashoffset = circumference - (report.score / 100) * circumference;
    scoreValueEl.textContent = report.score;

    scoreSection.classList.remove("grade-safe", "grade-warning", "grade-danger");
    scoreSection.classList.add(`grade-${report.grade}`);

    scoreLabelEl.textContent = report.grade === "safe" ? "This site looks safe." :
                               report.grade === "warning" ? "Some issues detected." : "High risk — be cautious!";

    issuesListEl.innerHTML = report.issues.length ? "" : '<li class="empty-state">No issues found — great!</li>';
    report.issues.forEach(issue => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="issue-badge ${issue.severity}"></span><div class="issue-text"><strong>${escapeHtml(issue.title)}</strong><span>${escapeHtml(issue.detail)}</span></div>`;
      issuesListEl.appendChild(li);
    });

    cookiesTotalEl.textContent = report.cookies.total;
    cookiesThirdEl.textContent = report.cookies.thirdParty;

    [downloadTxtBtn, downloadJsonBtn, downloadCsvBtn].forEach(btn => {
      if (btn) btn.disabled = false;
    });

    // Click handlers
    if (downloadTxtBtn) downloadTxtBtn.onclick = () => exportReport(report, "txt");
    if (downloadJsonBtn) downloadJsonBtn.onclick = () => exportReport(report, "json");
    if (downloadCsvBtn) downloadCsvBtn.onclick = () => exportReport(report, "csv");
  }

  // 4. Export logic
  function exportReport(report, format) {
    let content, type, ext;
    if (format === "json") {
      content = JSON.stringify(report, null, 2);
      type = "application/json";
      ext = "json";
    } else if (format === "csv") {
      const rows = [["Type", "Severity", "Title", "Detail"]];
      report.issues.forEach(i => rows.push([i.type, i.severity, i.title, i.detail]));
      content = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
      type = "text/csv";
      ext = "csv";
    } else {
      content = `VISIONGUARD SECURITY REPORT\nURL: ${report.url}\nScore: ${report.score}/100\n\nIssues:\n` + 
                report.issues.map(i => `[${i.severity.toUpperCase()}] ${i.title}: ${i.detail}`).join("\n");
      type = "text/plain";
      ext = "txt";
    }

    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `visionguard-report-${report.domain}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
});
