chrome.webRequest.onSendHeaders.addListener(
  function (info) {
    if (info.requestHeaders) {
      for (var i = 0; i < info.requestHeaders.length; i++) {
        if (info.requestHeaders[i].name.toLowerCase() === 'authorization') {
          const token = info.requestHeaders[i].value.split(' ')[1];
          if (token) {
            console.log("Azure Token:", token);
            chrome.storage.local.set({ 'tokenObj': { 'token': token, 'date': new Date().toLocaleTimeString() } });
          }
          break;
        }
      }
    }
  },
  // filters
  {
    urls: [
      "https://api.azrbac.mspim.azure.com/*",
    ]
  },
  ["requestHeaders"]
);



