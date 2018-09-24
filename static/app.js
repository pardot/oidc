function attemptGetCredential() {
  var req = new XMLHttpRequest();
  req.open("POST", "/credentialrequests", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialRequestOptions = req.response;
      publicKeyCredentialRequestOptions.challenge = Uint8Array.from(atob(publicKeyCredentialRequestOptions.challenge), c => c.charCodeAt(0));

      navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      }).then(function(credential) {
        console.log(credential);
      }).catch(function(err) {
        // TODO
        console.log("Credential get failed");
        console.log(err);
      });
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential get failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential get failed");
  };

  req.send(JSON.stringify({}));
}

function attemptRegistration() {
  var req = new XMLHttpRequest();
  req.open("POST", "/credentials", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialCreationOptions = req.response;
      publicKeyCredentialCreationOptions.challenge = Uint8Array.from(atob(publicKeyCredentialCreationOptions.challenge), c => c.charCodeAt(0));
      publicKeyCredentialCreationOptions.user.id = Uint8Array.from(atob(publicKeyCredentialCreationOptions.user.id), c => c.charCodeAt(0));

      navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      }).then(function(credential) {
        console.log(credential);
      }).catch(function(err) {
        // TODO
        console.log("Credential creation failed");
        console.log(err);
      });
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

function initiateAuthn(e) {
  e.preventDefault();
  attemptGetCredential()
}

function initiateRegistration(e) {
  e.preventDefault();
  attemptRegistration();
}

ready(function() {
  var ele = document.getElementById("authnForm");
  if (ele) {
    ele.addEventListener("submit", initiateAuthn);
  }

  var ele = document.getElementById("registrationLink");
  if (ele) {
    ele.addEventListener("click", initiateRegistration);
  }
});
