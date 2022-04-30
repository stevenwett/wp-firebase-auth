# WP Firebase Auth

## Setup

* Install using composer
* Set up a /private directory in your root
* Create a new RSA token in /private directory (see #Adding an RSA Token)
* Create a Google Service Account config and place in /private directory (see #Adding a Google Service Account Config)
* require_once the controllers in your functions.php
* Instantiate the Auth controller

### Adding an RSA Token

### Adding a Google Service Account Config

#### Example google-service-account.json
```json
{
  "type": "service_account",
  "project_id": "",
  "private_key_id": "",
  "private_key": "",
  "client_email": "",
  "client_id": "",
  "auth_uri": "",
  "token_uri": "",
  "auth_provider_x509_cert_url": "",
  "client_x509_cert_url": ""
}
```

