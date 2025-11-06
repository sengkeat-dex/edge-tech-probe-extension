// Simple OWASP detector - direct scanning without complex probe injection
console.log('Comprehensive OWASP content script loaded');

// Documentation links for JavaScript APIs
const apiDocumentationLinks = {
  'crypto.getRandomValues': 'https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues',
  'btoa': 'https://developer.mozilla.org/en-US/docs/Web/API/btoa',
  'atob': 'https://developer.mozilla.org/en-US/docs/Web/API/atob',
  'localStorage': 'https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage',
  'sessionStorage': 'https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage',
  'console.log': 'https://developer.mozilla.org/en-US/docs/Web/API/Console/log',
  'console.error': 'https://developer.mozilla.org/en-US/docs/Web/API/Console/error',
  'fetch': 'https://developer.mozilla.org/en-US/docs/Web/API/fetch',
  'XMLHttpRequest': 'https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest',
  'eval': 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
  'document.cookie': 'https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie',
  'IndexedDB': 'https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API',
  'WebSQL': 'https://developer.mozilla.org/en-US/docs/Web/API/Window/openDatabase'
};

// Enhanced OWASP detection patterns for all 10 categories
const owaspDetectionPatterns = [
  // A01:2021-Broken Access Control
  {
    owasp_id: "A01:2021-Broken Access Control",
    layer: "Client",
    type: "Access Control",
    sub_type: "CSRF Protection",
    component: "meta",
    signature_value: "_token",
    purpose: "CSRF token for form protection",
    risk_description: "Missing or weak CSRF protection can lead to unauthorized actions",
    attack_vector: "Cross-site request forgery attacks",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Implement proper CSRF tokens, use SameSite cookies, validate referrer headers",
    evidence_metric: "CSRF token presence",
    detect: function() {
      const findings = [];
      // Check for CSRF tokens in forms
      const csrfTokens = document.querySelectorAll('meta[name="csrf-token"], input[name="_token"], [data-csrf], [data-token"]');
      if (csrfTokens.length > 0) {
        findings.push({
          type: "DOM",
          details: "CSRF tokens found",
          value: `${csrfTokens.length} tokens detected`,
          link: null
        });
      }
      
      // Check for IDOR patterns (URL parameters that might be manipulatable)
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.size > 0) {
        findings.push({
          type: "JS",
          details: "URL parameters present",
          value: `${urlParams.size} parameters detected`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A02:2021-Cryptographic Failures
  {
    owasp_id: "A02:2021-Cryptographic Failures",
    layer: "Client",
    type: "Crypto API",
    sub_type: "WebCrypto",
    component: "crypto",
    signature_value: "getRandomValues",
    purpose: "Generate cryptographically secure random values",
    risk_description: "Weak randomness can lead to predictable values",
    attack_vector: "Insufficient entropy in random number generation",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Use crypto.subtle for cryptographic operations and ensure proper entropy sources",
    evidence_metric: "Entropy quality check",
    detect: function() {
      const findings = [];
      if (typeof window.crypto !== 'undefined' && typeof window.crypto.getRandomValues !== 'undefined') {
        findings.push({
          type: "JS",
          details: "crypto.getRandomValues",
          value: "[function:getRandomValues]",
          link: apiDocumentationLinks['crypto.getRandomValues']
        });
      }
      console.log('A02:2021-Cryptographic Failures detection result:', findings);
      return findings;
    }
  },
  {
    owasp_id: "A02:2021-Cryptographic Failures",
    layer: "Client",
    type: "Encoding",
    sub_type: "Base64 encode",
    component: "btoa",
    signature_value: "btoa",
    purpose: "Encode binary data to ASCII string",
    risk_description: "Sensitive data exposure in client storage",
    attack_vector: "Base64 encoded secrets in localStorage",
    impact: "Medium",
    likelihood: "High",
    severity: "Medium",
    control_type: "Detective",
    mitigation_strategy: "Use encrypted storage instead of encoding, or implement proper encryption before storage",
    evidence_metric: "Encoded secret count",
    detect: function() {
      const findings = [];
      if (typeof window.btoa !== 'undefined') {
        findings.push({
          type: "JS",
          details: "btoa",
          value: "[function:btoa]",
          link: apiDocumentationLinks['btoa']
        });
      }
      console.log('A02:2021-Cryptographic Failures (btoa) detection result:', findings);
      return findings;
    }
  },
  {
    owasp_id: "A02:2021-Cryptographic Failures",
    layer: "Client",
    type: "Encoding",
    sub_type: "Base64 decode",
    component: "atob",
    signature_value: "atob",
    purpose: "Decode ASCII string to binary data",
    risk_description: "Input decoding without validation",
    attack_vector: "Malicious Base64 input decoding",
    impact: "Medium",
    likelihood: "Medium",
    severity: "Medium",
    control_type: "Preventive",
    mitigation_strategy: "Validate and sanitize input before decoding, implement content security policies",
    evidence_metric: "Input validation percentage",
    detect: function() {
      const findings = [];
      if (typeof window.atob !== 'undefined') {
        findings.push({
          type: "JS",
          details: "atob",
          value: "[function:atob]",
          link: apiDocumentationLinks['atob']
        });
      }
      console.log('A02:2021-Cryptographic Failures (atob) detection result:', findings);
      return findings;
    }
  },
  
  // A03:2021-Injection
  {
    owasp_id: "A03:2021-Injection",
    layer: "Client",
    type: "Code Injection",
    sub_type: "Dynamic Code Execution",
    component: "eval",
    signature_value: "eval",
    purpose: "Evaluate JavaScript code represented as a string",
    risk_description: "Client-side code injection can lead to XSS and data theft",
    attack_vector: "Malicious script injection through user input",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Avoid using eval(), use JSON.parse() for JSON data, implement proper input validation",
    evidence_metric: "eval() usage count",
    detect: function() {
      const findings = [];
      // Check for eval usage in inline scripts
      const scripts = document.querySelectorAll('script');
      let evalCount = 0;
      scripts.forEach(script => {
        if (script.textContent && script.textContent.includes('eval(')) {
          evalCount++;
        }
      });
      
      if (evalCount > 0) {
        findings.push({
          type: "DOM",
          details: "eval() usage detected",
          value: `${evalCount} instances`,
          link: apiDocumentationLinks['eval']
        });
      }
      
      // Check for GET forms (potential for injection)
      const getForms = document.querySelectorAll('form[method="get"]');
      if (getForms.length > 0) {
        findings.push({
          type: "DOM",
          details: "form[method='get']",
          value: `${getForms.length} GET forms`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A04:2021-Insecure Design
  {
    owasp_id: "A04:2021-Insecure Design",
    layer: "Client",
    type: "Storage",
    sub_type: "Key-value store",
    component: "localStorage",
    signature_value: "localStorage",
    purpose: "Client-side persistent storage",
    risk_description: "Unencrypted secret storage",
    attack_vector: "XSS leading to localStorage access",
    impact: "High",
    likelihood: "High",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Use secure HTTP-only cookies, implement encryption for sensitive data, or use secure browser storage APIs",
    evidence_metric: "Secret scan count",
    detect: function() {
      const findings = [];
      if (typeof window.localStorage !== 'undefined') {
        findings.push({
          type: "JS",
          details: "localStorage",
          value: "[object Storage]",
          link: apiDocumentationLinks['localStorage']
        });
        try {
          if (localStorage.length > 0) {
            findings.push({
              type: "JS",
              details: "localStorage.length",
              value: localStorage.length.toString(),
              link: apiDocumentationLinks['localStorage']
            });
          }
        } catch (e) {
          // Ignore if access is restricted
        }
      }
      console.log('A04:2021-Insecure Design (localStorage) detection result:', findings);
      return findings;
    }
  },
  {
    owasp_id: "A04:2021-Insecure Design",
    layer: "Client",
    type: "Storage",
    sub_type: "Ephemeral store",
    component: "sessionStorage",
    signature_value: "sessionStorage",
    purpose: "Client-side session storage",
    risk_description: "Persistent session data leakage",
    attack_vector: "Session fixation attacks",
    impact: "Medium",
    likelihood: "Medium",
    severity: "Medium",
    control_type: "Preventive",
    mitigation_strategy: "Implement proper session expiration, use secure session management, encrypt session data",
    evidence_metric: "Session TTL compliance",
    detect: function() {
      const findings = [];
      if (typeof window.sessionStorage !== 'undefined') {
        findings.push({
          type: "JS",
          details: "sessionStorage",
          value: "[object Storage]",
          link: apiDocumentationLinks['sessionStorage']
        });
        try {
          if (sessionStorage.length > 0) {
            findings.push({
              type: "JS",
              details: "sessionStorage.length",
              value: sessionStorage.length.toString(),
              link: apiDocumentationLinks['sessionStorage']
            });
          }
        } catch (e) {
          // Ignore if access is restricted
        }
      }
      console.log('A04:2021-Insecure Design (sessionStorage) detection result:', findings);
      return findings;
    }
  },
  
  // A05:2021-Security Misconfiguration
  {
    owasp_id: "A05:2021-Security Misconfiguration",
    layer: "Client",
    type: "Metadata",
    sub_type: "Generator Tags",
    component: "meta",
    signature_value: "generator",
    purpose: "Identify website technology stack",
    risk_description: "Technology fingerprinting can aid attackers in targeting known vulnerabilities",
    attack_vector: "Information disclosure through meta tags",
    impact: "Medium",
    likelihood: "High",
    severity: "Medium",
    control_type: "Preventive",
    mitigation_strategy: "Remove or obfuscate generator tags, implement security headers, use generic server signatures",
    evidence_metric: "Generator tag presence",
    detect: function() {
      const findings = [];
      // Check for generator meta tags
      const generators = document.querySelectorAll('meta[name="generator"]');
      if (generators.length > 0) {
        findings.push({
          type: "DOM",
          details: 'meta[name="generator"]',
          value: `${generators.length} generator tags`,
          link: null
        });
      }
      
      // Check for debug scripts
      const debugScripts = document.querySelectorAll('script[src*="debug"], script[src*="test"]');
      if (debugScripts.length > 0) {
        findings.push({
          type: "DOM",
          details: 'Debug scripts detected',
          value: `${debugScripts.length} debug scripts`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A06:2021-Vulnerable and Outdated Components
  {
    owasp_id: "A06:2021-Vulnerable and Outdated Components",
    layer: "Client",
    type: "Library Version",
    sub_type: "Outdated Frameworks",
    component: "script",
    signature_value: "jquery/1.",
    purpose: "Identify outdated JavaScript libraries",
    risk_description: "Known vulnerabilities in outdated libraries can be exploited",
    attack_vector: "Exploitation of unpatched library vulnerabilities",
    impact: "High",
    likelihood: "High",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Regularly update dependencies, use dependency scanning tools, implement SRI for external resources",
    evidence_metric: "Outdated component count",
    detect: function() {
      const findings = [];
      // Check for outdated jQuery versions
      const jqueryScripts = document.querySelectorAll('script[src*="jquery/1."]');
      if (jqueryScripts.length > 0) {
        findings.push({
          type: "DOM",
          details: 'Outdated jQuery detected',
          value: `${jqueryScripts.length} outdated versions`,
          link: null
        });
      }
      
      // Check for outdated Angular versions
      const angularScripts = document.querySelectorAll('script[src*="angularjs/1."]');
      if (angularScripts.length > 0) {
        findings.push({
          type: "DOM",
          details: 'Outdated Angular detected',
          value: `${angularScripts.length} outdated versions`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A07:2021-Identification and Authentication Failures
  {
    owasp_id: "A07:2021-Identification and Authentication Failures",
    layer: "Client",
    type: "Authentication",
    sub_type: "Form Security",
    component: "form",
    signature_value: "autocomplete",
    purpose: "Control browser autocomplete behavior",
    risk_description: "Improper autocomplete settings can expose credentials",
    attack_vector: "Credential theft through browser autocomplete",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Use appropriate autocomplete values, implement secure password fields, use credential management APIs",
    evidence_metric: "Improper autocomplete usage",
    detect: function() {
      const findings = [];
      // Check for forms with autocomplete off
      const noAutocompleteForms = document.querySelectorAll('form[autocomplete="off"]');
      if (noAutocompleteForms.length > 0) {
        findings.push({
          type: "DOM",
          details: 'form[autocomplete="off"]',
          value: `${noAutocompleteForms.length} forms with autocomplete off`,
          link: null
        });
      }
      
      // Check for password fields with new-password
      const newPasswordFields = document.querySelectorAll('input[type="password"][autocomplete="new-password"]');
      if (newPasswordFields.length > 0) {
        findings.push({
          type: "DOM",
          details: 'input[type="password"][autocomplete="new-password"]',
          value: `${newPasswordFields.length} new-password fields`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A08:2021-Software and Data Integrity Failures
  {
    owasp_id: "A08:2021-Software and Data Integrity Failures",
    layer: "Client",
    type: "Resource Loading",
    sub_type: "Insecure Resources",
    component: "script",
    signature_value: "http://",
    purpose: "Load external resources",
    risk_description: "Loading resources over HTTP can lead to MITM attacks",
    attack_vector: "Man-in-the-middle attacks on resource loading",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Use HTTPS for all resources, implement SRI for external scripts, use CSP headers",
    evidence_metric: "Insecure resource count",
    detect: function() {
      const findings = [];
      // Check for insecure script sources
      const insecureScripts = document.querySelectorAll('script[src^="http://"]');
      if (insecureScripts.length > 0) {
        findings.push({
          type: "DOM",
          details: 'script[src^="http://"]',
          value: `${insecureScripts.length} insecure scripts`,
          link: null
        });
      }
      
      // Check for insecure link sources
      const insecureLinks = document.querySelectorAll('link[href^="http://"]');
      if (insecureLinks.length > 0) {
        findings.push({
          type: "DOM",
          details: 'link[href^="http://"]',
          value: `${insecureLinks.length} insecure links`,
          link: null
        });
      }
      return findings;
    }
  },
  
  // A09:2021-Security Logging and Monitoring Failures
  {
    owasp_id: "A09:2021-Security Logging and Monitoring Failures",
    layer: "Client",
    type: "Console",
    sub_type: "Debug output",
    component: "console.log",
    signature_value: "console.log",
    purpose: "Development debugging output",
    risk_description: "PII or sensitive data leak in logs",
    attack_vector: "Production logs containing sensitive info",
    impact: "Medium",
    likelihood: "High",
    severity: "Medium",
    control_type: "Preventive",
    mitigation_strategy: "Disable console logging in production, implement log filtering, use environment-based logging controls",
    evidence_metric: "Log scan count",
    detect: function() {
      const findings = [];
      if (typeof window.console !== 'undefined' && typeof window.console.log !== 'undefined') {
        findings.push({
          type: "JS",
          details: "console.log",
          value: "[function:log]",
          link: apiDocumentationLinks['console.log']
        });
      }
      console.log('A09:2021-Security Logging and Monitoring Failures (console.log) detection result:', findings);
      return findings;
    }
  },
  {
    owasp_id: "A09:2021-Security Logging and Monitoring Failures",
    layer: "Client",
    type: "Console",
    sub_type: "Error output",
    component: "console.error",
    signature_value: "console.error",
    purpose: "Error reporting output",
    risk_description: "Stack trace and system info leak",
    attack_vector: "Verbose error messages in production",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Mask sensitive error output, implement custom error handlers, use generic error messages in production",
    evidence_metric: "Error redaction percentage",
    detect: function() {
      const findings = [];
      if (typeof window.console !== 'undefined' && typeof window.console.error !== 'undefined') {
        findings.push({
          type: "JS",
          details: "console.error",
          value: "[function:error]",
          link: apiDocumentationLinks['console.error']
        });
      }
      console.log('A09:2021-Security Logging and Monitoring Failures (console.error) detection result:', findings);
      return findings;
    }
  },
  
  // A10:2021-Server-Side Request Forgery
  {
    owasp_id: "A10:2021-Server-Side Request Forgery",
    layer: "Client",
    type: "Network",
    sub_type: "HTTP request",
    component: "fetch",
    signature_value: "fetch",
    purpose: "Make HTTP requests",
    risk_description: "Dynamic URL injection leading to SSRF",
    attack_vector: "User-controlled URLs in fetch requests",
    impact: "High",
    likelihood: "Medium",
    severity: "High",
    control_type: "Preventive",
    mitigation_strategy: "Validate origin and implement Content Security Policy (CSP), use allowlists for URLs, implement request sanitization",
    evidence_metric: "Origin validation percentage",
    detect: function() {
      const findings = [];
      if (typeof window.fetch !== 'undefined') {
        findings.push({
          type: "JS",
          details: "fetch",
          value: "[function:fetch]",
          link: apiDocumentationLinks['fetch']
        });
      }
      console.log('A10:2021-Server-Side Request Forgery (fetch) detection result:', findings);
      return findings;
    }
  }
];

// Direct OWASP scan function
function runOWASPDetection() {
  console.log('Running enhanced OWASP detection based on CSV structure');
  const results = {
    dom: [],
    js: []
  };
  
  owaspDetectionPatterns.forEach(pattern => {
    try {
      const findings = pattern.detect();
      findings.forEach(finding => {
        if (finding.type === "DOM") {
          results.dom.push({
            name: pattern.owasp_id,
            selector: finding.details,
            property: pattern.purpose,
            value: finding.value,
            risk: pattern.risk_description,
            mitigation: pattern.mitigation_strategy,
            severity: pattern.severity,
            link: finding.link
          });
        } else if (finding.type === "JS") {
          results.js.push({
            name: pattern.owasp_id,
            chain: finding.details,
            value: finding.value,
            risk: pattern.risk_description,
            mitigation: pattern.mitigation_strategy,
            severity: pattern.severity,
            link: finding.link
          });
        }
      });
    } catch (error) {
      console.error(`Error detecting ${pattern.owasp_id}:`, error);
    }
  });
  
  console.log('OWASP detection results:', results);
  return results;
}

// Add detection patterns based on complete-trigger.js categories
const extendedDetectionPatterns = [
  // Security Telemetry - OSQuery-like detection
  {
    category: "Security Telemetry",
    subCategory: "Endpoint Sensors",
    name: "OSQuery Presence",
    type: "JS",
    chain: "window.osquery",
    purpose: "Agent-based endpoint monitoring",
    risk: "Endpoint visibility",
    mitigation: "Ensure proper agent management",
    severity: "Info",
    detect: function() {
      const findings = [];
      if (typeof window.osquery !== 'undefined') {
        findings.push({
          type: "JS",
          details: "window.osquery",
          value: "[object Object]",
          link: null
        });
      }
      return findings;
    }
  },
  
  // SIEM Integration - Log collection detection
  {
    category: "SIEM Integration",
    subCategory: "Log Collection",
    name: "Logging Framework",
    type: "JS",
    chain: "console",
    purpose: "Client-side logging",
    risk: "Information disclosure",
    mitigation: "Disable verbose logging in production",
    severity: "Medium",
    detect: function() {
      const findings = [];
      if (typeof window.console !== 'undefined') {
        findings.push({
          type: "JS",
          details: "window.console",
          value: "[object Console]",
          link: null
        });
      }
      return findings;
    }
  },
  
  // Alert Pipeline - Event monitoring
  {
    category: "Alert Pipeline",
    subCategory: "Event Monitoring",
    name: "Error Monitoring",
    type: "JS",
    chain: "window.onerror",
    purpose: "Client-side error capture",
    risk: "Error information leakage",
    mitigation: "Implement proper error handling",
    severity: "Medium",
    detect: function() {
      const findings = [];
      if (typeof window.onerror !== 'undefined') {
        findings.push({
          type: "JS",
          details: "window.onerror",
          value: typeof window.onerror === 'function' ? "[function]" : "[property]",
          link: null
        });
      }
      return findings;
    }
  },
  
  // Detection Testing - Test environment detection
  {
    category: "Detection Testing",
    subCategory: "Environment Detection",
    name: "Test Environment",
    type: "DOM",
    selector: "meta[name='env']",
    purpose: "Environment identification",
    risk: "Environment information disclosure",
    mitigation: "Remove environment markers in production",
    severity: "Low",
    detect: function() {
      const findings = [];
      const envMeta = document.querySelector('meta[name="env"]');
      if (envMeta) {
        findings.push({
          type: "DOM",
          details: 'meta[name="env"]',
          value: envMeta.getAttribute('content') || 'present',
          link: null
        });
      }
      return findings;
    }
  }
];

// Enhanced detection function that includes both OWASP and extended patterns
function runExtendedDetection() {
  console.log('Running extended detection based on complete-trigger.js');
  const results = {
    dom: [],
    js: []
  };
  
  // Run existing OWASP detection
  const owaspResults = runOWASPDetection();
  results.dom = [...owaspResults.dom];
  results.js = [...owaspResults.js];
  
  // Run extended detection patterns
  extendedDetectionPatterns.forEach(pattern => {
    try {
      const findings = pattern.detect();
      findings.forEach(finding => {
        if (finding.type === "DOM") {
          results.dom.push({
            name: `${pattern.category} - ${pattern.name}`,
            selector: finding.details,
            property: pattern.purpose,
            value: finding.value,
            risk: pattern.risk,
            mitigation: pattern.mitigation,
            severity: pattern.severity,
            link: finding.link
          });
        } else if (finding.type === "JS") {
          results.js.push({
            name: `${pattern.category} - ${pattern.name}`,
            chain: finding.details,
            value: finding.value,
            risk: pattern.risk,
            mitigation: pattern.mitigation,
            severity: pattern.severity,
            link: finding.link
          });
        }
      });
    } catch (error) {
      console.error(`Error detecting ${pattern.name}:`, error);
    }
  });
  
  console.log('Extended detection results:', results);
  return results;
}

// Add synthetic testing capabilities inspired by complete-trigger.js
const SyntheticTestGenerators = {
  // Generate synthetic OSQuery-like presence
  generateOSQuery: () => {
    window.osquery = {
      version: "1.0.0",
      platform: "browser-extension-test"
    };
  },
  
  // Generate synthetic logging activity
  generateLogging: () => {
    console.log("Synthetic log entry for testing");
    console.warn("Synthetic warning for testing");
    console.error("Synthetic error for testing");
  },
  
  // Generate synthetic error handler
  generateErrorHandler: () => {
    window.onerror = function(message, source, lineno, colno, error) {
      console.log("Synthetic error handler triggered");
      return true;
    };
  },
  
  // Generate test environment meta tag
  generateTestEnvironment: () => {
    const meta = document.createElement('meta');
    meta.name = "env";
    meta.content = "testing";
    document.head.appendChild(meta);
  }
};

// Add synthetic test function
function runSyntheticTests() {
  console.log('Running synthetic tests to validate detection capabilities');
  
  // Generate synthetic artifacts
  SyntheticTestGenerators.generateOSQuery();
  SyntheticTestGenerators.generateLogging();
  SyntheticTestGenerators.generateErrorHandler();
  SyntheticTestGenerators.generateTestEnvironment();
  
  // Run detection on synthetic artifacts
  return runExtendedDetection();
}

// Update the message listener to use extended detection
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('Content script received message:', msg);
  
  if (msg?.type === 'RUN_SCAN') {
    // Run extended detection
    const results = runExtendedDetection();
    
    // Send results back
    try {
      chrome.runtime.sendMessage({
        type: 'PROBE_RESULT',
        payload: results,
        url: window.location.href
      }).catch(error => {
        console.error('Error sending probe result:', error);
      });
    } catch (error) {
      console.error('Exception sending probe result:', error);
    }
    
    sendResponse({ ok: true });
    return false;
  }
  
  if (msg?.type === 'RUN_SYNTHETIC_TESTS') {
    // Run synthetic tests and then detection
    const results = runSyntheticTests();
    
    // Send results back
    try {
      chrome.runtime.sendMessage({
        type: 'PROBE_RESULT',
        payload: results,
        url: window.location.href
      }).catch(error => {
        console.error('Error sending synthetic test result:', error);
      });
    } catch (error) {
      console.error('Exception sending synthetic test result:', error);
    }
    
    sendResponse({ ok: true });
    return false;
  }
});

console.log('Enhanced OWASP content script ready');