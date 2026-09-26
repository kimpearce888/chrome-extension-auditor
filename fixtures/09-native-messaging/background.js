
const port = chrome.runtime.connectNative("com.example.nativeapp");
chrome.runtime.sendNativeMessage("com.example.nativeapp", {cmd: "hello"}, (resp) => {
  console.log(resp);
});
chrome.runtime.onMessageExternal.addListener((msg, sender) => {
  if (sender.id) return true;
});
