let lastResult = null;
let currentUrl = null;

function getActiveTab() {
  return new Promise(resolve => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      resolve(tabs[0]);
    });
  });
}

async function runScan() {
  console.log('Starting scan...');
  const tab = await getActiveTab();
  
  if (!tab?.id) {
    document.getElementById('meta').textContent = 'Error: No active tab';
    return;
  }
  
  try {
    console.log('Sending RUN_SCAN message to tab:', tab.id);
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_SCAN' });
    console.log('Received response from content script:', response);
    
    if (response && response.ok === false) {
      document.getElementById('meta').textContent = `Error: ${response.error || 'Scan failed'}`;
      return;
    }
    document.getElementById('meta').textContent = 'Scanning...';
  } catch (error) {
    console.error('Scan error:', error);
    if (error.message.includes('Could not establish connection') || 
        error.message.includes('Receiving end does not exist') ||
        error.message.includes('Extension context invalidated')) {
      document.getElementById('meta').textContent = 'Error: Extension not ready. Please refresh the page and try again.';
    } else if (error.message.includes('Invalid tab')) {
      document.getElementById('meta').textContent = 'Error: Invalid tab. Please try again.';
    } else {
      document.getElementById('meta').textContent = `Error: ${error.message}`;
    }
  }
}

async function runSyntheticTests() {
  console.log('Starting synthetic tests...');
  const tab = await getActiveTab();
  
  if (!tab?.id) {
    document.getElementById('meta').textContent = 'Error: No active tab';
    return;
  }
  
  try {
    console.log('Sending RUN_SYNTHETIC_TESTS message to tab:', tab.id);
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_SYNTHETIC_TESTS' });
    console.log('Received response from content script:', response);
    
    if (response && response.ok === false) {
      document.getElementById('meta').textContent = `Error: ${response.error || 'Synthetic tests failed'}`;
      return;
    }
    document.getElementById('meta').textContent = 'Running synthetic tests...';
  } catch (error) {
    console.error('Synthetic test error:', error);
    if (error.message.includes('Could not establish connection') || 
        error.message.includes('Receiving end does not exist') ||
        error.message.includes('Extension context invalidated')) {
      document.getElementById('meta').textContent = 'Error: Extension not ready. Please refresh the page and try again.';
    } else if (error.message.includes('Invalid tab')) {
      document.getElementById('meta').textContent = 'Error: Invalid tab. Please try again.';
    } else {
      document.getElementById('meta').textContent = `Error: ${error.message}`;
    }
  }
}

function render(result, url) {
  console.log('Rendering results:', result);
  lastResult = result;
  currentUrl = url;
  const { dom = [], js = [] } = result;
  
  // Extract findings by category from the extended detection
  const findingsByCategory = {};
  
  // Collect all findings and organize by category
  [...dom, ...js].forEach(item => {
    // Extract category from the name (format: "Category - Name" or "OWASP ID")
    let category = "Other";
    if (item.name.includes(" - ")) {
      category = item.name.split(" - ")[0];
    } else if (item.name.includes("OWASP")) {
      category = "OWASP Top 10";
    }
    
    if (!findingsByCategory[category]) {
      findingsByCategory[category] = [];
    }
    findingsByCategory[category].push(item);
  });
  
  console.log('Findings by category:', findingsByCategory);
  
  const domCols = ['name','selector','property','value'];
  const jsCols = ['name','chain','value'];
  const detailedCols = ['name', 'property', 'value', 'severity'];

  const toTable = (rows, cols) => {
    // Create header
    let tableHtml = '<table><thead><tr>';
    cols.forEach(col => {
      tableHtml += `<th>${col}</th>`;
    });
    tableHtml += '</tr></thead><tbody>';
    
    // Create rows
    rows.forEach(row => {
      tableHtml += '<tr>';
      cols.forEach(col => {
        let cellValue = row[col] || '';
        if (col === 'link' && cellValue) {
          cellValue = `<a href="${cellValue}" target="_blank">Documentation</a>`;
        } else if (col === 'details' && row.link) {
          // Make the details clickable if there's a link
          cellValue = `<a href="${row.link}" target="_blank">${cellValue}</a>`;
        }
        tableHtml += `<td>${cellValue}</td>`;
      });
      tableHtml += '</tr>';
    });
    
    tableHtml += '</tbody></table>';
    return tableHtml;
  };

  // Generate category-specific sections
  let categorySections = '';
  Object.keys(findingsByCategory).forEach(category => {
    const findings = findingsByCategory[category];
    console.log(`Generating section for ${category} with ${findings.length} findings`);
    categorySections += `
      <h4>${category} (${findings.length} findings)</h4>
      ${toTable(findings, detailedCols)}
    `;
  });

  document.getElementById('results').innerHTML = `
    ${Object.keys(findingsByCategory).length > 0 ? `
      <h3>Detection Results by Category</h3>
      ${categorySections}
    ` : '<h3>No findings detected</h3>'}
    <details>
      <summary>DOM Details (${dom.length})</summary>
      ${dom.length ? toTable(dom, domCols) : '<em>No DOM data.</em>'}
    </details>
    <details>
      <summary>JS Details (${js.length})</summary>
      ${js.length ? toTable(js, jsCols) : '<em>No JS data.</em>'}
    </details>
  `;
  
  // Count total findings
  const totalFindings = Object.values(findingsByCategory).reduce((sum, findings) => sum + findings.length, 0);
  document.getElementById('meta').textContent = `Found ${totalFindings} findings across ${Object.keys(findingsByCategory).length} categories`;
  document.getElementById('export-json').disabled = false;
  document.getElementById('export-csv').disabled = false;
}

// Add export helpers similar to those in complete-trigger.js
function toCSVExtended(results, url) {
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
  const { dom = [], js = [] } = results;
  
  // Flatten findings with category information
  const allFindings = [
    ...dom.map(item => ({ ...item, type: 'DOM' })),
    ...js.map(item => ({ ...item, type: 'JS' }))
  ];
  
  const header = [
    "Type",
    "Category",
    "Name", 
    "Selector/Chain",
    "Property/Value",
    "Severity",
    "Risk",
    "Mitigation"
  ];
  
  const lines = [header.map(esc).join(",")];
  
  allFindings.forEach(item => {
    // Extract category from name
    let category = "Other";
    if (item.name.includes(" - ")) {
      category = item.name.split(" - ")[0];
    } else if (item.name.includes("OWASP")) {
      category = "OWASP Top 10";
    }
    
    const row = [
      item.type,
      category,
      item.name,
      item.type === 'DOM' ? item.selector : item.chain,
      item.type === 'DOM' ? item.property : item.value,
      item.severity || 'N/A',
      item.risk || 'N/A',
      item.mitigation || 'N/A'
    ].map(esc).join(",");
    
    lines.push(row);
  });
  
  return lines.join("\n");
}

// Set up event listeners when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Popup DOM loaded');
  
  // Add event listeners
  document.getElementById('scan').addEventListener('click', runScan);
  document.getElementById('synthetic-test').addEventListener('click', runSyntheticTests);
  document.getElementById('export-json').addEventListener('click', () => {
    if (!lastResult) return;
    const exportData = {
      url: currentUrl,
      timestamp: new Date().toISOString(),
      results: lastResult
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    chrome.downloads.download({ url: URL.createObjectURL(blob), filename: 'probe-result.json' });
  });
  document.getElementById('export-csv').addEventListener('click', () => {
    if (!lastResult) return;
    
    // Use enhanced CSV export
    const csv = toCSVExtended(lastResult, currentUrl);
    const blob = new Blob([`# Scan Results for ${currentUrl || 'Unknown URL'}\n# Timestamp: ${new Date().toISOString()}\n\n${csv}`], { type: 'text/csv' });
    chrome.downloads.download({ url: URL.createObjectURL(blob), filename: 'probe-result-extended.csv' });
  });
  
  // Try to run an initial scan when popup opens, with a delay to ensure everything is ready
  setTimeout(() => {
    console.log('Attempting initial scan');
    runScan();
  }, 1000);
});

// Keep the existing message listener
chrome.runtime.onMessage.addListener(msg => {
  console.log('Popup received message:', msg);
  if (msg?.type === 'PROBE_RESULT') {
    console.log('Received probe result:', msg.payload);
    render(msg.payload, msg.url);
  }
});

console.log('Popup script loaded');