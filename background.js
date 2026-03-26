/**
 * VisionGuard — Background Service Worker
 * Scans each visited page for security issues.
 */

importScripts("utils/analyzer.js");

const tabReports = {};

// ── Capture Response Headers ────────────────────────────────────────────
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;

    const headers = {};
    for (const h of details.responseHeaders || []) {
      headers[h.name.toLowerCase()] = h.value;
    }

    if (!tabReports[details.tabId]) tabReports[details.tabId] = {};
    tabReports[details.tabId].headers = headers;
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ── Full Scan Logic ─────────────────────────────────────────────────────
async function performScan(tabId, urlStr) {
  try {
    const url = new URL(urlStr);
    const domain = url.hostname;

    // 1. Get Cookies
    let cookies = [];
    try {
      cookies = await chrome.cookies.getAll({ url: urlStr });
    } catch (_) {}

    // 2. Get DOM Issues from Content Script
    let domIssues = [];
    try {
      const response = await chrome.tabs.sendMessage(tabId, { action: "scanDOM" });
      if (response && response.issues) {
        domIssues = response.issues;
      }
    } catch (_) {
      // Content script might not be ready or injected
    }

    const headers = (tabReports[tabId] && tabReports[tabId].headers) || {};

    // 3. Build Report
    const report = Analyzer.buildReport({
      headers,
      url: urlStr,
      cookies,
      domain,
      domIssues
    });

    tabReports[tabId] = { ...tabReports[tabId], report };
    await chrome.storage.local.set({ [`report_${tabId}`]: report });

    // 4. Show Banner if Danger
    if (report.grade === "danger") {
      chrome.tabs.sendMessage(tabId, {
        action: "showBanner",
        score: report.score,
        issueCount: report.issues.length,
      }).catch(() => {});
    }

    return report;
  } catch (err) {
    console.error("VisionGuard scan error:", err);
  }
}

// ── Event Listeners ─────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    performScan(tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabReports[tabId];
  chrome.storage.local.remove(`report_${tabId}`);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getReport") {
    const tabId = message.tabId;
    const cached = tabReports[tabId] && tabReports[tabId].report;

    if (cached) {
      sendResponse({ report: cached });
    } else {
      chrome.storage.local.get(`report_${tabId}`, (result) => {
        sendResponse({ report: result[`report_${tabId}`] || null });
      });
      return true;
    }
  }
});
