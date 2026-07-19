chrome.runtime.onInstalled.addListener(() => {
});

async function fetchWithFallback(url, options) {
  let controller, timer;
  try {
    controller = new AbortController();
    timer = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(url, { ...options, mode: 'cors', signal: controller.signal });
    clearTimeout(timer);
    return { resp, mode: 'cors' };
  } catch (e) {
    clearTimeout(timer);
    if (e.name === 'TypeError' || e.name === 'AbortError') {
      try {
        controller = new AbortController();
        timer = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(url, { ...options, mode: 'no-cors', signal: controller.signal });
        clearTimeout(timer);
        return { resp, mode: 'no-cors' };
      } catch (e2) {
        clearTimeout(timer);
        return { error: true };
      }
    }
    return { error: true };
  }
}

async function checkUrl(url, method) {
  const result = await fetchWithFallback(url, { method: method || 'HEAD' });
  if (result.error) return { error: true };
  if (result.mode === 'no-cors') {
    return { status: 0, type: 'opaque' };
  }
  try {
    return {
      status: result.resp.status,
      type: result.resp.type,
      xfo: result.resp.headers.get('X-Frame-Options') || '',
      csp: result.resp.headers.get('Content-Security-Policy') || ''
    };
  } catch (e) {
    return { status: result.resp.status, type: result.resp.type };
  }
}

async function checkUrlContent(url) {
  const result = await fetchWithFallback(url, { method: 'GET' });
  if (result.error) return { error: true };
  if (result.mode === 'no-cors') {
    return { status: 0, type: 'opaque' };
  }
  try {
    if (result.resp.status === 404 || result.resp.status === 410 || result.resp.status >= 500) {
      return { status: result.resp.status, error: 'http_error' };
    }
    const text = (await result.resp.text()).slice(0, 4096);
    return { status: result.resp.status, text: text };
  } catch (e) {
    return { status: result.resp.status };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'checkFrame') {
    checkUrl(message.url).then((result) => {
      if (result.error) {
        sendResponse({ ok: false, reason: 'fetch_error' });
        return;
      }
      if (result.type === 'opaque') {
        sendResponse({ ok: true });
        return;
      }
      if (result.status >= 400) {
        sendResponse({ ok: false, reason: 'http_' + result.status });
        return;
      }
      const xfo = result.xfo;
      if (xfo) {
        const v = xfo.toUpperCase();
        if (v === 'DENY' || v === 'SAMEORIGIN') {
          sendResponse({ ok: false, reason: 'xfo' });
          return;
        }
      }
      const csp = result.csp;
      if (csp) {
        const m = csp.match(/frame-ancestors\s+([^;]+)/i);
        if (m) {
          const val = m[1].trim();
          if (val === "'none'" || val === "'self'") {
            sendResponse({ ok: false, reason: 'csp' });
            return;
          }
          if (!val.includes('*')) {
            sendResponse({ ok: false, reason: 'csp' });
            return;
          }
        }
      }
      sendResponse({ ok: true });
    });
    return true;
  }
  if (message.type === 'checkDead') {
    checkUrl(message.url).then((result) => {
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'checkDeadContent') {
    checkUrlContent(message.url).then((result) => {
      sendResponse(result);
    });
    return true;
  }
});
