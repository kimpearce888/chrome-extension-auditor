#!/usr/bin/env python3
"""Creates the §179 test fixture extensions under fixtures/."""
import json, os, base64, random

BASE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(BASE, "..", "fixtures")

def fixture(name, manifest, files):
    d = os.path.join(FIX, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    for path, content in files.items():
        full = os.path.join(d, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as f:
            f.write(content)
    print("created", name)

MV3 = 3

# 1. Simple extension
fixture("01-simple", {
    "manifest_version": MV3, "name": "Simple Fixture", "version": "1.0.0",
    "description": "Minimal well-behaved extension",
    "action": {"default_popup": "popup.html"},
    "permissions": ["storage"],
    "background": {"service_worker": "background.js"},
}, {
    "background.js": "chrome.runtime.onInstalled.addListener(() => { chrome.storage.local.set({installed: true}); });\n",
    "popup.html": "<!DOCTYPE html><html><body><h1>Hello</h1><script src=\"popup.js\"></script></body></html>",
    "popup.js": "document.querySelector('h1').textContent = 'Hello from Simple';\n",
})

# 2. Large extension (many files)
files = {"big.js": "function pad() { return '" + "x" * 200000 + "'; }\n"}
for i in range(60):
    files[f"lib/module{i}.js"] = f"export const m{i} = () => {i}; // " + "y" * 500 + "\n"
fixture("02-large", {
    "manifest_version": MV3, "name": "Large Fixture", "version": "1.0.0",
    "action": {"default_popup": "popup.html"},
    "background": {"service_worker": "background.js"},
}, {**files, "popup.html": "<html><body>Large</body></html>",
    "background.js": "console.log('large');\n"})

# 3. Minified extension
minified = 'var a="min",b=function(c){return c+1};for(var i=0;i<10;i++){b(i)};console.log(a);' + 'var x%d=%d;' % (1,1)
minified += "".join(f'var v{j}={j};' for j in range(3000))
fixture("03-minified", {
    "manifest_version": MV3, "name": "Minified Fixture", "version": "1.0.0",
    "action": {"default_popup": "popup.html"},
    "background": {"service_worker": "bg.min.js"},
}, {"bg.min.js": minified, "popup.html": "<html><body>Min</body></html>"})

# 4. Content-script-heavy extension
fixture("04-content-heavy", {
    "manifest_version": MV3, "name": "Content Heavy Fixture", "version": "1.0.0",
    "permissions": ["storage", "tabs"],
    "host_permissions": ["<all_urls>"],
    "content_scripts": [
        {"matches": ["<all_urls>"], "js": ["cs1.js", "cs2.js"], "css": ["cs.css"],
         "run_at": "document_start", "all_frames": True},
        {"matches": ["https://example.com/*"], "js": ["cs3.js"], "run_at": "document_idle"},
    ],
    "background": {"service_worker": "background.js"},
}, {
    "cs1.js": "console.log('cs1');\n" * 50,
    "cs2.js": "console.log('cs2');\n" * 50,
    "cs3.js": "console.log('cs3');\n",
    "cs.css": "body { color: red; }\n",
    "background.js": "chrome.runtime.onInstalled.addListener(()=>{});\n",
})

# 5. Permission-heavy extension
fixture("05-permission-heavy", {
    "manifest_version": MV3, "name": "Permission Heavy Fixture", "version": "1.0.0",
    "permissions": ["cookies", "history", "bookmarks", "webNavigation", "downloads",
                    "clipboardRead", "clipboardWrite", "management", "identity", "geolocation"],
    "host_permissions": ["<all_urls>", "http://*/*", "file:///*"],
    "optional_permissions": ["debugger", "proxy", "privacy"],
    "action": {"default_popup": "popup.html"},
}, {"popup.html": "<html><body>Perms</body></html>",
    "background.js": "chrome.runtime.onInstalled.addListener(()=>{});\n"})

# 6. Network-heavy extension
fixture("06-network-heavy", {
    "manifest_version": MV3, "name": "Network Heavy Fixture", "version": "1.0.0",
    "host_permissions": ["https://api.example.com/*", "https://cdn.example.net/*"],
    "background": {"service_worker": "background.js"},
}, {"background.js": """
fetch("https://api.example.com/v1/data");
fetch("https://analytics.example.net/collect", {method: "POST"});
const xhr = new XMLHttpRequest();
xhr.open("GET", "https://cdn.example.net/lib.js");
xhr.send();
const ws = new WebSocket("wss://rt.example.org/socket");
navigator.sendBeacon("https://beacon.example.io/t", "ping");
fetch(`https://dyn.example.com/${path}`);
fetch(buildUrl());
const es = new EventSource("https://stream.example.dev/events");
"""})

# 7. Timer-heavy extension
fixture("07-timer-heavy", {
    "manifest_version": MV3, "name": "Timer Heavy Fixture", "version": "1.0.0",
    "background": {"service_worker": "background.js"},
}, {"background.js": """
setInterval(poll, 10);
setInterval(poll2, 50);
setInterval(poll3, 250);
setTimeout(init, 100);
setTimeout("doSomething()", 500);
function poll() {}
function poll2() {}
function poll3() {}
function init() {}
function doSomething() {}
"""})

# 8. MutationObserver-heavy extension
fixture("08-observer-heavy", {
    "manifest_version": MV3, "name": "Observer Heavy Fixture", "version": "1.0.0",
    "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}],
}, {"cs.js": """
const obs = new MutationObserver((muts) => {
  for (const m of muts) console.log(m.type);
});
obs.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
setInterval(() => document.querySelectorAll('div'), 100);
document.querySelectorAll('a');
document.querySelectorAll('p');
document.querySelectorAll('span');
document.querySelectorAll('li');
document.querySelectorAll('ul');
document.querySelectorAll('table');
document.querySelectorAll('img');
document.querySelectorAll('input');
document.querySelectorAll('form');
document.querySelectorAll('section');
document.querySelectorAll('header');
document.querySelectorAll('footer');
"""})

# 9. Native-messaging fixture
fixture("09-native-messaging", {
    "manifest_version": MV3, "name": "Native Messaging Fixture", "version": "1.0.0",
    "permissions": ["nativeMessaging", "storage"],
    "background": {"service_worker": "background.js"},
}, {"background.js": """
const port = chrome.runtime.connectNative("com.example.nativeapp");
chrome.runtime.sendNativeMessage("com.example.nativeapp", {cmd: "hello"}, (resp) => {
  console.log(resp);
});
chrome.runtime.onMessageExternal.addListener((msg, sender) => {
  if (sender.id) return true;
});
"""})

# 10. Malformed manifest
fixture("10-malformed-manifest", {}, {"manifest.json": "{ this is not valid json !!!",
    "background.js": "console.log('never parsed');\n"}) if False else None
# (manifest written below with raw text)
d = os.path.join(FIX, "10-malformed-manifest")
os.makedirs(d, exist_ok=True)
with open(os.path.join(d, "manifest.json"), "w") as f:
    f.write("{ this is not valid json !!!")
with open(os.path.join(d, "background.js"), "w") as f:
    f.write("console.log('never parsed');\n")
print("created 10-malformed-manifest")

# 11. Missing-file fixture
fixture("11-missing-files", {
    "manifest_version": MV3, "name": "Missing Files Fixture", "version": "1.0.0",
    "background": {"service_worker": "does-not-exist.js"},
    "content_scripts": [{"matches": ["<all_urls>"], "js": ["also-missing.js"]}],
    "action": {"default_popup": "nope.html"},
}, {})

# 12. Obfuscated-code fixture
random.seed(42)
_b64 = base64.b64encode(os.urandom(4096)).decode()
obf = f"""
var _0x1a2b = ['\\x68\\x65\\x6c\\x6c\\x6f', '\\x77\\x6f\\x72\\x6c\\x64'];
var _0x3c4d = function(_0x5e6f) {{ return _0x1a2b[_0x5e6f]; }};
var _0x99aa = 1;
var _0x7788 = atob("{_b64}");
eval(_0x3c4d(0));
new Function(_0x3c4d(1))();
"""
fixture("12-obfuscated", {
    "manifest_version": MV3, "name": "Obfuscated Fixture", "version": "1.0.0",
    "background": {"service_worker": "bg.js"},
}, {"bg.js": obf})

# 13. Large-package fixture (single big asset)
big_blob = "QmFzZTY0IGJsb2Ig" * 90000  # ~1.1MB
fixture("13-large-package", {
    "manifest_version": MV3, "name": "Large Package Fixture", "version": "1.0.0",
    "web_accessible_resources": [{"resources": ["data.json", "app.js"], "matches": ["<all_urls>"]}],
    "action": {"default_popup": "popup.html"},
}, {"data.json": json.dumps({"blob": big_blob[:500000]}),
    "app.js": "console.log('app');\n",
    "popup.html": "<html><body>Big</body></html>"})

# Bonus: MV2 legacy fixture (compatibility)
fixture("14-legacy-mv2", {
    "manifest_version": 2, "name": "Legacy MV2 Fixture", "version": "2.4.1",
    "permissions": ["tabs", "webRequest", "webRequestBlocking", "storage"],
    "background": {"scripts": ["background.js"], "persistent": True},
    "browser_action": {"default_popup": "popup.html"},
    "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.example.com; object-src 'self'",
}, {"background.js": """
chrome.tabs.executeScript(null, {file: 'injected.js'});
chrome.browserAction.onClicked.addListener(() => {});
chrome.extension.getURL('x.html');
""",
    "popup.html": "<html><body>MV2</body></html>",
    "injected.js": "document.write('hi');\n"})

print("All fixtures created.")
