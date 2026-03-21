function loadResult() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab    = tabs[0];
        const tabId  = tab.id;
        const url    = tab.url;

        chrome.storage.local.get([`tab_${tabId}`], (data) => {
            const result    = data[`tab_${tabId}`];
            const container = document.getElementById('result');

            if (!result) {
                setTimeout(loadResult, 500);
                return;
            }

            const isPhishing = result.final === 'phishing';
            const prob       = (result.rf_probability * 100).toFixed(1);
            const rfResult   = result.rf_prediction;
            const isoResult  = result.iso_prediction;

            container.innerHTML = `
                <div class="status-icon">${isPhishing ? '🚨' : '✅'}</div>
                <div class="status-text ${isPhishing ? 'phishing' : 'safe'}">
                    ${isPhishing ? 'PHISHING DETECTED' : 'SAFE'}
                </div>
                <div class="confidence">
                    Confidence: ${result.confidence} &nbsp;|&nbsp;
                    Probability: ${prob}%
                </div>
                ${isPhishing ? `
                <div class="warning-banner">
                    ⚠ This page may be attempting to steal your credentials.
                    Do not enter any personal information.
                </div>` : ''}
                <div class="url-box">${url}</div>
                <div class="metrics">
                    <div class="metric-card">
                        <div class="metric-val">${prob}%</div>
                        <div class="metric-label">Phishing Probability</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-val">${result.confidence}</div>
                        <div class="metric-label">Confidence Level</div>
                    </div>
                </div>
                <div class="models">
                    <div class="model-tag ${rfResult === 'phishing' ? 'phishing' : 'safe'}">
                        RF: ${rfResult.toUpperCase()}
                    </div>
                    <div class="model-tag ${isoResult === 'phishing' ? 'phishing' : 'safe'}">
                        IF: ${isoResult.toUpperCase()}
                    </div>
                </div>
            `;
        });
    });
}

loadResult();