// background.js
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // only act when URL changes (or page loaded)
  const url = changeInfo.url || tab?.url;
  if (!url) return;

  // call local API
  fetch("http://127.0.0.1:5000/api/predict", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({url})
  })
  .then(r => r.json())
  .then(data => {
    // show warning if phishing confidence high
    if (data.prediction === "Phishing" && data.confidence >= 60) {
      chrome.scripting.executeScript({
        target: {tabId: tabId},
        func: showWarningInPage,
        args: [data]
      });
    }
  })
  .catch(err => {
    console.log("PhishGuard: API call error", err);
    // optional: fallback heuristic
  });
});

// This function will be executed inside the page context
function showWarningInPage(data) {
  if (window.__phishguard_modal_shown) return;
  window.__phishguard_modal_shown = true;

  const modal = document.createElement('div');
  modal.id = 'phishguard-modal';
  modal.style = 'position:fixed;top:10%;left:50%;transform:translateX(-50%);z-index:2147483647;width:90%;max-width:700px;background:#fff;border:2px solid #c00;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,.4);font-family:Arial, sans-serif;';
  modal.innerHTML = `
    <h2 style="margin:0;color:#b30000">⚠️ Suspicious Site Detected</h2>
    <p style="margin:.5em 0"><strong>Confidence:</strong> ${data.confidence}%</p>
    <p style="margin:.5em 0"><strong>Reason:</strong> ${data.vt || 'Model flagged URL'}</p>
    <div style="text-align:right;margin-top:10px;">
      <button id="phg-block" style="margin-right:8px;padding:8px 12px">Block</button>
      <button id="phg-proceed" style="padding:8px 12px">Proceed</button>
    </div>
  `;
  document.documentElement.appendChild(modal);

  document.getElementById('phg-block').onclick = () => {
    // block: replace page content (simple)
    document.documentElement.innerHTML = '<div style="padding:40px;font-family:Arial"><h1 style="color:#c00">Blocked by PhishGuard</h1><p>This site was blocked for your safety.</p></div>';
    fetch('http://127.0.0.1:5000/api/log_action', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:location.href, action:'block'})});
  };
  document.getElementById('phg-proceed').onclick = () => {
    modal.remove();
    fetch('http://127.0.0.1:5000/api/log_action', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:location.href, action:'proceed'})});
  };
}
