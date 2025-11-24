# Let's Encrypt ACME2 project

A PHP client for acme protocal (version 2) implementation, used to get let's encrypt ssl certificates. Support for both RSA and ECDSA certificates is supported. The code will not set the challenge file or DNS record for you, you must handle these manually.

> This project was forked from (https://github.com/stonemax/acme2) and fully upgraded to use guzzlehttp/guzzle package as the http request handler. It also fixes deprecations from newer versions of php, specifically php 8. This project fully supports php 8.1 and assumes that since all the deprecations are fixed, it will work with php 9 as well when it is released. This project is only compatibile with php 8.1 or newer as of April 2025.

## 1. Current Version

The current version is `1.0.5`.

## 2. Prerequisites

This project works with PHP-8.1.0 or higher. You must install PHP and ext-curl, ext-openssl, and ext-json. Guzzle requires json, and intl for Internationalized Domain Name (IDN) support.

## 3. Install

Install requires executing `/usr/bin/php composer.phar require orangecam/acme2letsencrypt`.

## 4. Usage

The basic methods and its necessary arguments are shown here. An example is supplied in the file [exampleRunScript.php](https://github.com/orangecam/acme2letsencrypt/blob/master/exampleRunScript.php).

#### 4.1. Initial setup

```php
//Pull in the ClientRequest to use it
use orangecam\acme2letsencrypt\ClientRequest;

// Email list as contact info
$emailList = ['alert@example.com'];
// Account data and certificates files will be stored here
$sslDir = '/var/www/ssl/';
// Hostname without the TLD ***not*** to include the '.' (dot)
$name = 'example';
// TLD here, for example 'com' ***not*** to include the '.' (dot)
$topLevelDomain = 'com';
// Using stage environment or not, make sure to empty $sslDir directory after you change from staging/test server to the real one
$useStagingUrl = FALSE;
// Initiating a client
$client = new ClientRequest(
	$emailList,
	$sslDir.$name.'_'.$topLevelDomain,
	$useStagingUrl
);
```
After `ClientRequest` had been initiated, a Let's Encrypt account will be created and the account data will be placed in ` $sslDir.$name.'_'.$topLevelDomain`.
When you reinitialize the client, the account will not be created again.

#### 4.2. Account Management

```php
// Get account service instance
$account = $client->getAccount();
//-----------------------------------
// Update account contact info with an email list
$account->updateAccountContact($emailList);
//-----------------------------------
// Regenerate private/public key pair，the old will be replaced by the new
$account->updateAccountKey();
//-----------------------------------
// Deactive the account
$account->deactivateAccount();
```

#### 4.3. Order
These methods bellow are mainly used for generating certificates.

```php
//Pull in the ConstantVariables to use it in the code below
use orangecam\acme2letsencrypt\constants\ConstantVariables;

/* Domains and challenges info for a single certificate with multiple SAN: abc.example.com, *.example.com and example.com */
$domainInfo = [
	ConstantVariables::CHALLENGE_TYPE_HTTP => [
		//WILDCARD certs not allowed on HTTP challenge type
		'example.com',
		'www.example.com',
	],
];
//----------OR----------
$domainInfo = [
	ConstantVariables::CHALLENGE_TYPE_DNS => [
		'example.com',
		'*.example.com',
	],
];
// Generate RSA certificates, `ConstantVariables::KEY_PAIR_TYPE_EC` for ECDSA certificates
$algorithm = ConstantVariables::KEY_PAIR_TYPE_RSA;
// Get an order service instance
$order = $client->getOrder($domainInfo, $algorithm, TRUE);
```

```php
//The prototype of method `getOrder()` is shown below:
public function getOrder(array $domainInfo, int $algorithm, bool $generateNewOder = TRUE): OrderService
```

The third param `$generateNewOder` controls whether a new order need to be generated. When `$generateNewOder == TRUE`, all files under original certificates directory will be removed in order to generate new certificates; When `$generateNewOder == FALSE`, it will return an existing order service instance used to revoke certificates generally.

#### 4.4. Challenge

```php
// Get all authorization challenges for domains
$challengeList = $order->getPendingChallengeList();
//Loop through the list
foreach($challengeList as $challenge) {
	//Get the credentials
	$credential = $challenge->getCredential();
	//Get the type
	$type = $challenge->getType();

	//****Push the $credentials to the right place. HTTP-01 or DNS-01

	//Infinite loop until the authorization status becomes valid or timeout has been reached
	$challenge->verify(700, 700);
}
// Get certificates, such as certificates path, private/public key pair path, valid time
$order->getCertificateFile();
// Revoke certificates, the certificaes ara unavailable after revoked
$order->revokeCertificate($reason);
```

```php
//The prototype of method `verify()` is shown below:
public function verify(int $verifyLocallyTimeout = 0, int $verifyCATimeout = 0): bool
```
* The first param `$verifyLocallyTimeout` stands for the timeout of local verification. Default value 0 won't trigger time-out mechanism.

* The second param `$verifyCATimeout` stand for the timeout of Let's Encrypt verification. Default value 0 won't trigger time-out mechanism.

## 5. Domain Verification
When generating a certificate, Let's Encrypt needs to verify the ownership and validity of the domain. There are two types of verification: http-01, dns-01.
In the following, we take `example.com` as an example.

#### 5.1. http-01
Let's Encrypt will access a specific file under web server to verify domain. The `$challenge` info is like bellow.

```php
print_r($challenge->getType());
/* output */
'http-01'

print_r($challenge->getCredential());
/* output */
[
	'identifier' => 'example.com',
	'fileName' => 'RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y',
	'fileContent' => 'RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y.CNWZAGtAHIUpstBEckq9W_-0ZKxO-IbxF9Y8J_svbqo',
];
```

With the above `$challenge` info, Let's Encrypt will access "http://example.com/.well-known/acme-challenge/HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y", and the file content will be expected as "RzMY-HDa1P0DwZalmRyB7wLBNI8fb11LkxdXzNrhA1Y.CNWZAGtAHIUpstBEckq9W_-0ZKxO-IbxF9Y8J_svbqo".

#### 5.2. dns-01
You should add a DNS TXT record for domain, Let's Encrypt will check domain's specific TXT record value for verification.
As this time, the `$challenge` info is like bellow.

```php
print_r($challenge->getType());
/* output */
'dns-01'

print_r($challenge->getCredential());
/* output */
[
	'identifier' => 'example.com',
	'dnsContent' => 'xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk',
];
```

With the aboved `$challenge` info, you should add a TXT record for domain `example.com`, the record name should be "_acme-challenge.example.com", the record value should be "xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk".
It's worth noting that you should set TTL as short as possible to let the record take effect as soon as possible.

#### 5.3. Wildcard domain verification
This tool supports generating certificates for wildcard domains.
A wildcard domain, like `*.example.com`, will be verified as `example.com`, this means the DNS record name should be `_acme-challenge.example.com`.
Here is a simple summary for dns-01 challenges about domain and DNS record.

|       Domain       |         DNS record name          | Type | TTL |       DNS record value(just examples)       |
| ------------------ | -------------------------------- | ---- | --- | ------------------------------------------- |
| example.com        | \_acme-challenge.example.com     | TXT  |  60 | xQwerUEsL8UVc6tIahwIVY4e8N5MAf1xhyY20AELurk |
| \*.example.com     | \_acme-challenge.example.com     | TXT  |  60 | G2dOkzSjW3ohib5doPRDrz5a5l8JB1qU8CxURtzF7aE |

## 7. Full example
Project supplies a [full example](https://github.com/orangecam/acme2letsencrypt/blob/master/exampleRunScript.php).

## 8. Finish
I hope you find this project useful to you and allows you to automate the generating of ssl certs on your own website.
