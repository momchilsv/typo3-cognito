.. ==================================================
.. FOR YOUR INFORMATION
.. --------------------------------------------------
.. -*- coding: utf-8 -*- with BOM.


TYPO3 CMS Extension "cognito"
=============================
The extension provides a Typo3 frontend users authentication service for users stored in Amazon Cognito cloud platform via json web tokens (jwt).

Requirements
------------
- TYPO3 CMS 7.6 / probably will work in v8 as well /
- PHP 5.5+
- Amazon Cognito users setup
- JWT authentication tokens, signed with RS512


Installation
------------

The extension is published in TER (Typo3 Extensions Repository) and can be installed from the extensions manager.
Your frontend users have to be stored in the Amazon Cognito cloud platform.

Extension configuration
-----------------------
- **OpenID Provider Configuration URI**: JSON document with OpenID Provider Configuration Information (usually https://{provider}/.well-known/openid-configuration). Default value: https://cognito-identity.amazonaws.com/.well-known/openid-configuration
- **Get param name for jwt**: $_GET param, which holds the 'jwt' token. Default valie: jwt
- **Storage users folder UID**: Storage system folder, where all new cognito users will be saved locally
- **User group UID**: User group for all newly created local cognito users
- **Priority**: The priority is used to define a call order for services. The service with the highest priority is called first. The default range is 0-100. Default value: 85
- **Quality**: Among services with the same priority, the service with the highest quality, but the same priority will be preferred. The default range is 0-100. Default value: 85

Authentication
--------------
The typo3 cognito authentication is triggered, when you pass the get param 'logintype=login' and the get param 'jwt=', which contains the jwt cognito token. The name of the get param, which holds the token, is configurable via the extension manager and has a default value 'jwt':

http:/dev.project/index.php?logintype=login&jwt={amazon-cognito-jwt-token}

The jwt token's payload part must contain the user cognito ID as a 'sub' property of the json object. **Currently no other user data from the payload jwt part is used in Typo3.** Users are checked locally based on the user cognito ID and if a local user with such ID does not exist, then a new user is created in the 'fe_users' table.

Technical background
--------------------
- Authentication services in Typo3 https://docs.typo3.org/typo3cms/Typo3ServicesReference/Authentication/Index.html
- Amazon Cognito https://aws.amazon.com/cognito/
- JWT https://jwt.io/
- RSA (cryptosystem) https://en.wikipedia.org/wiki/RSA_(cryptosystem)

TO DO
-----
- Supports other jwt encryption algorithms
- Use more user data from the jwt payload part
- Test the extension in Typo3 v8 LTS