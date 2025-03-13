document.addEventListener('DOMContentLoaded', function () {
  const targetUrl = 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup/provider/aadgroup';
  var azureTokenLink = document.getElementById('azureTokenLink');

  // Set the link to navigate in the current tab or refresh if the same URL
  azureTokenLink.addEventListener('click', function(event) {
    event.preventDefault();  // Prevent the default action

    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      // Check if the current URL is the same as the target URL
      if (tabs[0].url.includes(targetUrl)) {
        chrome.tabs.reload(tabs[0].id);  // Reload the current tab
      } else {
        chrome.tabs.update(tabs[0].id, {url: targetUrl});  // Navigate to the target URL in the current tab
      }
    });
  });

  // Create or get a reference to the checkbox
  var autoDownloadCheckbox = document.getElementById('autoDownload') || createAutoDownloadCheckbox();

  // Restore checkbox state and last expiration date
  chrome.storage.local.get(['autoDownloadEnabled', 'lastDownloadedExp'], function (result) {
    autoDownloadCheckbox.checked = result.autoDownloadEnabled || false;
    var lastDownloadedExp = result.lastDownloadedExp || 0;
    initializeExtension(lastDownloadedExp);
  });

  function initializeExtension(lastDownloadedExp) {
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
          navigator.clipboard.writeText(tokenElem.value).then(function () {
            console.log('Token automatically copied to clipboard');
          }).catch(function (err) {
            console.error('Failed to automatically copy token to clipboard', err);
          });
          if (autoDownloadCheckbox.checked && decodedJwt.exp !== lastDownloadedExp) {
            downloadToken(tokenElem.value, ticketElem.value);
            chrome.storage.local.set({lastDownloadedExp: decodedJwt.exp});
          }
        } else {
          if (tabs[0].url !== targetUrl) {
            chrome.tabs.create({url: targetUrl});
          } else {
            setTimeout(window.location.reload(), 1000);
          }
        }

        document.getElementById('copyButton').addEventListener('click', function () {
          navigator.clipboard.writeText(tokenElem.value);
        });

        document.getElementById('saveButton').addEventListener('click', function () {
          downloadToken(tokenElem.value, ticketElem.value);
        });
      });
    });
  }

  // Event listener for the checkbox
  autoDownloadCheckbox.addEventListener('change', function () {
    chrome.storage.local.set({autoDownloadEnabled: autoDownloadCheckbox.checked});
  });

  function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  }

  function downloadToken(token, ticket) {
    var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      jwt: token,
      ticket: ticket
    }));
    var downloader = document.createElement('a');
    downloader.href = dataStr;
    downloader.download = 'azurejwt.json';
    downloader.click();
  }

  function createAutoDownloadCheckbox() {
    var label = document.createElement('label');
    var checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = 'autoDownload';
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode('Auto-Download Token'));
    document.body.appendChild(label);
    return checkbox;
  }
});
