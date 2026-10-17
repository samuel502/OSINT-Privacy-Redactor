# Constraints & Testing Framework

This document outlines the operational constraints, test cases, and pass/fail verification criteria for the OSINT Privacy Redactor agent.

## 🛡️ Core Constraints
1. **Zero-Cost Default Execution:** The core tool must function entirely using free, open-source Python libraries (`holehe`) and local vector retrieval without requiring paid commercial API subscriptions.
2. **Graceful Fallback on Anti-Automation:** If target websites enforce CAPTCHAs, bot protection (Cloudflare), or require manual validation links, the system must gracefully pivot to generating pre-formatted legal copy-paste templates rather than crashing.
3. **Optional API Key Injection:** Advanced users may optionally supply external API keys (e.g., CAPTCHA solvers or broker integration keys) to unlock full end-to-end automation.

---

## 🧪 Test Cases & Verification Criteria

### Test Case 1: Footprint Probe Reliability
* **Objective:** Verify that `holehe` / Tool 1 correctly executes and outputs structured data without hanging or crashing on invalid inputs.
* **Input:** A valid test email string (`test@example.com`).
* **Expected Output:** A structured JSON object containing a list of discovered platforms and a clean success status code.
* **Pass/Fail Criteria:** Pass if the script successfully parses JSON output within 30 seconds; fail if unhandled exceptions or timeout errors occur.

### Test Case 2: Policy & Legal Retrieval Accuracy
* **Objective:** Verify that Tool 2 correctly retrieves relevant GDPR/CCPA deletion guidelines and direct contact URLs for matched platforms.
* **Input:** A platform query string (e.g., `"Twitter"` or `"Spotify"`).
* **Expected Output:** Correct policy text snippet and direct privacy desk contact link retrieved from the vector database.
* **Pass/Fail Criteria:** Pass if semantic similarity matching retrieves the exact data record with a relevance score above 0.85.

### Test Case 3: Graceful Degradation / Fallback Generation
* **Objective:** Verify that when automated form submission or network requests are blocked, the agent successfully creates a manual suppression email draft.
* **Input:** Target platform with active anti-bot protection and no user-provided automation API key.
* **Expected Output:** A fully populated legal opt-out text block containing user details and data protection references.
* **Pass/Fail Criteria:** Pass if the system outputs a clean, ready-to-copy email template instead of failing execution.
