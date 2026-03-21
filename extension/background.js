// background.js — service worker
// Receives prediction results from content.js
// Stores result and updates extension icon

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PREDICTION_RESULT') {
        const result = message.result;
        const tabId  = sender.tab.id;

        // Store result for this tab
        chrome.storage.local.set({
            [`tab_${tabId}`]: result
        });

        // Update icon color based on result
        if (result.final === 'phishing') {
            // Red icon for phishing
            chrome.action.setBadgeText({
                text:  '⚠',
                tabId: tabId
            });
            chrome.action.setBadgeBackgroundColor({
                color: '#ff0000',
                tabId: tabId
            });
        } else {
            // Green icon for safe
            chrome.action.setBadgeText({
                text:  '✓',
                tabId: tabId
            });
            chrome.action.setBadgeBackgroundColor({
                color: '#00aa00',
                tabId: tabId
            });
        }
    }
});