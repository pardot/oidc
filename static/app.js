function attemptGetCredential(publicKeyCredentialRequestOptions) {
  navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  }).then(function(credential) {
    console.log(credential);
  }).catch(function(err) {
    // TODO
    console.log("Credential get failed");
    console.log(err);
  });
}

function initiateAuthn(e) {
  e.preventDefault();

  var req = new XMLHttpRequest();
  req.open("POST", "/credentials", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialRequestOptions = req.response;
      publicKeyCredentialRequestOptions.challenge = Uint8Array.from(atob(publicKeyCredentialRequestOptions.challenge), c => c.charCodeAt(0));
      attemptGetCredential(publicKeyCredentialRequestOptions);
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential creation failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential creation failed");
  };

  req.send(JSON.stringify({}));
}

ready(function() {
  document.getElementById("authnForm").addEventListener("submit", initiateAuthn);
});
