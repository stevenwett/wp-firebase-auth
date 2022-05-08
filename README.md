# WP Firebase Auth

## Setup

* Install using composer
* Set up a /private directory in your root
* Create a new RSA token in /private directory (see #Adding an RSA Token)
* Create a Google Service Account config and place in /private directory (see #Adding a Google Service Account Config)
* require_once the controllers in your functions.php
* Instantiate the Auth controller

### Adding an RSA Token
In terminal go to your /private directory and then use the following commands:
```
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```

### Adding a Google Service Account Config
* Go into your project in the Firebase Console, go to Project settings (gear top right sidebar) and then Service accounts.
* Click Generate new private key and it'll show you some json to copy. To see an example see #Example google-service-account.json
* Add json to file named google-service-account.json that is in the /private folder.

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

## Auth Endpoints
### Sign In
POST `/wp-json/wp-firebase-auth/v1/login`

Request body:
```json
{
  "email": "",
  "password": ""
}
```
* `email` and `password` are required.

Response body:
```json
{
  "message": "",
}
```
* 200: Signed in.
* 400: Bad request.

### Sign Out
POST `/wp-json/wp-firebase-auth/v1/logout`

* Must be authenticated.

Response body:
```json
{
  "message": "",
}
```
* 200: Signed out.
* 400: Bad request.

### Reset Password
POST `/wp-json/wp-firebase-auth/v1/reset-password`

* Must be authenticated.

Response body:
```json
{
  "message": "",
}
```
* 200: Password reset.
* 400: Bad request.


