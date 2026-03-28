# VisionGuard 🛡️

VisionGuard is a lightweight, real-time browser security analyzer designed to inspect websites for potential threats, misconfigurations, and privacy risks. It provides actionable insights and alerts to help users browse with confidence.

## 🚀 Key Features

- **Real-Time Scanning**: Automatically analyzes every page you visit for security headers and protocol safety.
- **Vulnerability Detection**: Identifies potential XSS scripts, open redirects, and insecure forms in the DOM.
- **Privacy Monitoring**: Detects tracking scripts, fingerprinting attempts, and excessive third-party cookies.
- **Phishing Heuristics**: Scans URLs for suspicious keywords, malicious TLDs, and IP-based hostnames.
- **Comprehensive Reporting**: View detailed security scores (0-100) and specific issues in the popup dashboard.
- **Export Formats**: Download security reports in **JSON**, **CSV**, or **TXT** format for further analysis.
- **Security Alerts**: Injects a warning banner on high-risk sites to keep you informed.

## 🛠️ Installation

1.  Clone or download this repository.
2.  Open Chrome and navigate to `chrome://extensions/`.
3.  Enable **Developer mode** in the top right corner.
4.  Click **Load unpacked** and select the `visionguard-extension` folder.

## 🧪 Testing the Extension

We have included a test suite to verify all security detections:

1.  Open [test_vulnerabilities.html](test_vulnerabilities.html) after installing the extension.
2.  Review the **Warning Banner** that appears on the page.
3.  Open the **VisionGuard Popup** to see the detected issues, including:
    - Potential XSS scripts
    - Tracking scripts (GA, FB, etc.)
    - Fingerprinting heuristics (Canvas + multiple trackers)
    - Open redirect parameters

## 📁 Project Structure

- `manifest.json`: Configuration and permissions.
- `background.js`: Main service worker coordinating the analysis.
- `content.js`: DOM scanner and alert banner injector.
- `utils/analyzer.js`: Core logic for scoring and heuristic detection.
- `popup/`: UI files for the extension dashboard.

## 🔒 Privacy & Security

VisionGuard is designed with privacy in mind. It performs all analysis locally in your browser and does not send your browsing data to any external servers. Logs are kept minimal and do not expose sensitive user information.

## Author 
Vision KC<br>
[Github](https://github.com/vision-dev1)<br>
[Portfolio](https://visionkc.com.np)

---
