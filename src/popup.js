document.addEventListener('DOMContentLoaded', function () {
  chrome.storage.local.get('tokenObj', function (res) {
    var tokenElem = document.getElementById('token');
    var dateElem = document.getElementById('date_acquired');
    console.log(JSON.stringify(res));
    tokenElem.value = res.tokenObj.token;
    dateElem.innerHTML = 'Acquired: ' + res.tokenObj.date;

    // Select the token text
    tokenElem.focus();
    tokenElem.select();
    document.getElementById('token').focus();
    document.getElementById('copyButton').addEventListener('click', function () {
      navigator.clipboard.writeText(tokenElem.value).then(function () {
        console.log('Text successfully copied to clipboard');
      }).catch(function (err) {
        console.error('Unable to copy text to clipboard', err);
      });
    });
  });
});

