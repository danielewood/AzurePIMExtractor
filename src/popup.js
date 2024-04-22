document.addEventListener('DOMContentLoaded', function () {
  const targetUrl = 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup/provider/aadgroup';

  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    chrome.storage.local.get('tokenObj', function (res) {
      var tokenElem = document.getElementById('token');
      var expiresElem = document.getElementById('minutes_remaining');
      var ticketElem = document.getElementById('ticket');

      tokenElem.value = res.tokenObj.token;
      const decodedJwt = parseJwt(tokenElem.value);
      const now = Math.floor(Date.now() / 1000);
      const minutesRemaining = Math.floor((decodedJwt.exp - now) / 60);

      expiresElem.innerText = minutesRemaining > 0 ? `${minutesRemaining} minutes` : "expired";

      if (decodedJwt.exp > now) {
        // Token is valid, automatically copy to clipboard
        navigator.clipboard.writeText(tokenElem.value).then(function () {
          console.log('Token automatically copied to clipboard');
        }).catch(function (err) {
          console.error('Failed to automatically copy token to clipboard', err);
        });
      } else if (tabs[0].url !== targetUrl) {
        // Redirect only if the token is expired and we're not on the target URL
        chrome.tabs.create({url: targetUrl});
      }

      document.getElementById('copyButton').addEventListener('click', function () {
        navigator.clipboard.writeText(tokenElem.value);
      });

      document.getElementById('saveButton').addEventListener('click', function () {
        var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
          jwt: tokenElem.value,
          ticket: ticketElem.value
        }));
        var downloader = document.createElement('a');
        downloader.href = dataStr;
        downloader.download = 'azurejwt.json';
        downloader.click();
      });
    });
  });

  function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  }
});
