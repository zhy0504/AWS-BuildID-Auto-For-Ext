/**
 * Offscreen Document - 用于绑定扩展权限执行跨域请求
 * 解决 Service Worker fetch CORS 限制问题
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'OFFSCREEN_FETCH') {
    handleFetch(message.url, message.options)
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

async function handleFetch(url, options = {}) {
  const method = options.method || 'GET';
  const xhr = new XMLHttpRequest();

  return new Promise((resolve, reject) => {
    xhr.open(method, url, true);

    if (options.headers) {
      for (const [key, value] of Object.entries(options.headers)) {
        xhr.setRequestHeader(key, value);
      }
    }

    xhr.onload = () => {
      const responseText = xhr.responseText || '';

      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const data = JSON.parse(responseText);
          resolve(data);
        } catch (e) {
          resolve(responseText);
        }
      } else {
        const bodyPreview = responseText
          ? `, body: ${responseText.slice(0, 200)}`
          : '';
        reject(new Error(`HTTP ${xhr.status}: ${xhr.statusText || 'Request failed'} (${method} ${url})${bodyPreview}`));
      }
    };

    xhr.onerror = () => {
      let origin = url;
      try {
        origin = new URL(url).origin;
      } catch {
        // ignore invalid URL parse
      }
      reject(new Error(`Network error (${method} ${origin})，可能是未授予域名权限或目标服务拒绝跨域请求`));
    };
    xhr.ontimeout = () => reject(new Error(`Request timeout (${method} ${url})`));
    xhr.timeout = 30000;

    xhr.send(options.body || null);
  });
}
