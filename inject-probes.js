/* eslint-env browser */
/**
 * inject-probes.js
 *
 * Unified DOM+JS probes (Wappalyzer-style), hardened:
 * - Safe JS path walking (getter-aware; avoids side effects where possible)
 * - Prototype + own-property access (fewer false negatives)
 * - Bounded serialization (JSON with cycle + DOM-node elision)
 * - Result + string caps to protect performance
 * - Single-run listener ({ once: true })
 * - Scoped postMessage targetOrigin (defaults to window.origin or '*')
 *
 * Expected trigger message shape (from content script):
 *   window.postMessage({ wappalyzer: { technologies: [...] } }, '*')
 *
 * Produces (posts back to page):
 *   window.postMessage({ wappalyzer: { dom: [...], js: [...] } }, targetOrigin)
 */

;(() => {
  console.log('Inject-probes script STARTING - this should appear when script is injected');
  
  // ---------------------------
  // Configuration
  // ---------------------------
  const cfg = {
    enableDom: true,
    enableJs: true,
    maxResults: 4000,           // hard cap across dom+js rows
    maxStringLen: 800,          // truncate long strings/JSON
    targetOrigin: window.origin || '*', // tighten if you control the receiver
    avoidCrossWindowPaths: true, // skips paths containing top/parent/opener (COOP/COEP safety)
    idleBatching: false,         // turn on if your tech list is huge
  };

  // ---------------------------
  // Utilities
  // ---------------------------
  const NOT_FOUND = Symbol('NOT_FOUND');
  const isObj = (v) => typeof v === 'object' && v !== null;
  const cap = (s, n) => (typeof s === 'string' && s.length > n ? s.slice(0, n) + '...' : s);

  const safeJSONStringify = (value, capLen) => {
    try {
      const seen = new WeakSet();
      let json = JSON.stringify(value, (k, v) => {
        if (isObj(v)) {
          if (seen.has(v)) return '[circular]';
          seen.add(v);
          // Don't dump DOM nodes
          if (v.nodeType && v.nodeName) return `[Node:${v.nodeName}]`;
        }
        return v;
      });
      return cap(json ?? 'true', capLen);
    } catch {
      return 'true';
    }
  };

  // Serialize to a compact, bounded scalar
  const toScalar = (v) => {
    if (v == null) return v; // null/undefined
    const t = typeof v;
    if (t === 'string') return cap(v, cfg.maxStringLen);
    if (t === 'number' || t === 'boolean') return v;
    if (t === 'function') return `[function${v.name ? ':' + v.name : ''}]`;
    if (v === '[getter]') return v; // our getter marker
    return safeJSONStringify(v, cfg.maxStringLen);
  };

  // Guard risky cross-window references if requested
  const pathIsSafe = (segments) => {
    if (!cfg.avoidCrossWindowPaths) return true;
    const risky = new Set(['top', 'parent', 'opener']);
    return !segments.some((s) => risky.has(s));
  };

  /**
   * Safe path resolution:
   *  - Allows prototype chain (`in` operator)
   *  - Avoids invoking getters when we can detect them via descriptor
   *  - Catches exceptions from host objects
   * Returns either the resolved value or NOT_FOUND
   */
  const getByPath = (root, segments) => {
    let cur = root;

    for (const seg of segments) {
      if (cur == null) return NOT_FOUND;

      // Some host objects throw on reflection; guard it.
      let desc;
      try {
        desc = Object.getOwnPropertyDescriptor(cur, seg);
      } catch {
        // ignore and fallback to `in`/direct access attempt
      }

      if (!desc) {
        try {
          if (!(seg in cur)) return NOT_FOUND;
          // Access might hit a getter; guard
          try {
            cur = cur[seg];
          } catch {
            return NOT_FOUND;
          }
        } catch {
          return NOT_FOUND;
        }
      } else if ('get' in desc && typeof desc.get === 'function') {
        // Don't invoke getters; mark presence
        cur = '[getter]';
      } else if ('value' in desc) {
        cur = desc.value;
      } else {
        return NOT_FOUND;
      }
    }

    return typeof cur === 'undefined' ? NOT_FOUND : cur;
  };

  // ---------------------------
  // DOM probing
  // ---------------------------
  const runDomProbe = (technologies, out, budget) => {
    let used = 0;

    for (const { name, dom } of technologies) {
      if (!dom || typeof dom !== 'object') continue;

      for (const selector of Object.keys(dom)) {
        let nodes;
        try {
          nodes = document.querySelectorAll(selector);
        } catch {
          continue; // invalid selector
        }
        if (!nodes || !nodes.length) continue;

        const entries = dom[selector] || [];
        for (const node of nodes) {
          for (const { properties } of entries) {
            if (!properties) continue;

            for (const prop of Object.keys(properties)) {
              let val;
              try {
                // Accept own or prototype props; guard access
                val = node[prop];
              } catch {
                continue;
              }
              if (typeof val !== 'undefined') {
                out.dom.push({
                  name,
                  selector,
                  property: prop,
                  value: toScalar(val),
                });
                used++;
                if (used >= budget) return used;
              }
            }
          }
        }
      }
    }

    return used;
  };

  // ---------------------------
  // JS chain probing
  // ---------------------------
  const runJsProbe = (technologies, out, budget) => {
    let used = 0;

    for (const { name, chains } of technologies) {
      if (!Array.isArray(chains)) continue;

      for (const chain of chains) {
        if (typeof chain !== 'string' || !chain) continue;

        const segments = chain.split('.').filter(Boolean);
        if (!pathIsSafe(segments)) continue;

        const val = getByPath(window, segments);
        if (val !== NOT_FOUND) {
          out.js.push({
            name,
            chain,
            value: toScalar(val),
          });
          used++;
          if (used >= budget) return used;
        }
      }
    }

    return used;
  };

  // ---------------------------
  // Orchestrator
  // ---------------------------
  const postBack = (payload) => {
    console.log('Probe script posting back results:', payload);
    try {
      window.postMessage({ wappalyzer: payload }, cfg.targetOrigin);
    } catch {
      // Fallback (older environments / sandboxed iframes that shim postMessage)
      try {
        postMessage({ wappalyzer: payload });
      } catch {
        // fail quietly
        console.error('Failed to post message back');
      }
    }
  };

  const handleMessage = ({ data, origin }) => {
    console.log('Probe script received message:', data, 'from origin:', origin);
    if (!data || !data.wappalyzer || !data.wappalyzer.technologies) {
      console.log('Invalid message format, ignoring');
      return;
    }

    const technologies = data.wappalyzer.technologies;
    console.log('Processing technologies:', technologies.length);
    const out = { dom: [], js: [] };
    let remaining = cfg.maxResults;

    const run = () => {
      console.log('Running DOM probe');
      if (cfg.enableDom && remaining > 0) {
        const domCount = runDomProbe(technologies, out, remaining);
        console.log('DOM probe found:', domCount, 'items');
        remaining -= domCount;
      }
      console.log('Running JS probe');
      if (cfg.enableJs && remaining > 0) {
        const jsCount = runJsProbe(technologies, out, remaining);
        console.log('JS probe found:', jsCount, 'items');
        remaining -= jsCount;
      }
      console.log('Posting back results:', out);
      postBack(out);
    };

    if (cfg.idleBatching && 'requestIdleCallback' in window) {
      // Spread work if needed
      requestIdleCallback(() => run(), { timeout: 1500 });
    } else {
      run();
    }
  };

  // Persistent listener: runs for every trigger payload.
  console.log('Adding message listener to probe script');
  addEventListener('message', handleMessage, { once: false });
  
  // Also listen for direct postMessage calls
  if (window !== window.parent || window !== window.top) {
    // In iframe, also listen on window
    window.addEventListener('message', handleMessage, { once: false });
  }
  
  console.log('Inject-probes script INITIALIZATION COMPLETE');
})()