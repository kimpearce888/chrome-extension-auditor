
chrome.tabs.executeScript(null, {file: 'injected.js'});
chrome.browserAction.onClicked.addListener(() => {});
chrome.extension.getURL('x.html');
