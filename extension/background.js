// background.js
// Handles API calls (fix for CORS / HTTPS issue)

chrome.runtime.onMessage.addListener((message, sender) => {

    // STEP 1: Receive features from content.js
    if (message.type === 'ANALYZE_URL') {

        fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: message.url,
                features: message.features
            })
        })
        .then(res => res.json())
        .then(result => {

            const tabId = sender.tab.id;

            // Send back to content script
            chrome.tabs.sendMessage(tabId, {
                type: 'PREDICTION_RESULT',
                result: result
            });

            // Store result
            chrome.storage.local.set({
                [`tab_${tabId}`]: result
            });

            // Update badge
            if (result.final === 'phishing') {
                chrome.action.setBadgeText({ text: '⚠', tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#ff0000', tabId });
            } else {
                chrome.action.setBadgeText({ text: '✓', tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#00aa00', tabId });
            }
        })
        .catch(err => {
            console.error("Background fetch error:", err);
        });
    }

});