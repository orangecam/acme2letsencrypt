<?php
require 'vendor/autoload.php';

use orangecam\acme2letsencrypt\ClientRequest;
use orangecam\acme2letsencrypt\constants\ConstantVariables;
use GuzzleHttp\Client as GuzzleHttpClient;

class Run
{
	/**
	 * Get ssl cert using HTTP-01 as verification method for site ownership
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['test@test.com']
	 * @param $subDomainName:string ex: dev
	 * @param $baseDomainName:string ex: test
	 * @param $TLD:string ex: com
	 * @param $pathToWwwRoot:string ex: /var/www/hosts/
	 * @param $renewCert:bool ex: FALSE
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function getSslCert_usingHttp(
		string $sslDir = "",
		array $emailList = [],
		string $subDomainName = "",
		string $baseDomainName = "",
		string $TLD = 'com',
		string $pathToWwwRoot = '/var/www/hosts/',
		bool $renewCert = FALSE,
		bool $useStagingUrl = FALSE
	): void
	{
		//Check to make sure pathToWwwRoot has a / at the end
		if(!str_ends_with($pathToWwwRoot, '/')) {
			//Append / to the end if missing
			$pathToWwwRoot .= '/';
		}
		//Setup the domain_name to use
		$combinedDomainNameUnderscore = $baseDomainName.'_'.$TLD;
		//If $subDommainName is not empty, then reset the combinedDomainNameUnderscore
		if(!empty($subDomainName)) {
			$combinedDomainNameUnderscore = $subDomainName.'_'.$baseDomainName.'_'.$TLD;
		}
		//If not renewing the cert, then remove old files
		if($renewCert == FALSE) {
			if(!file_exists($sslDir.$combinedDomainNameUnderscore)) {
				mkdir($sslDir.$combinedDomainNameUnderscore, 0755, false);
			}
			$files = scandir($sslDir.$combinedDomainNameUnderscore);
			$files = array_diff($files, array('.', '..'));
			foreach($files as $index => $dir_name) {
				if(is_dir($sslDir.$combinedDomainNameUnderscore.DIRECTORY_SEPARATOR.$dir_name) && $dir_name != "account") {
					$this->rmdirRecursive($sslDir.$combinedDomainNameUnderscore.DIRECTORY_SEPARATOR.$dir_name);
				}
			}
		}
		//Get both the RSA and EC keys
		$order_list = [
			ConstantVariables::KEY_PAIR_TYPE_RSA,
			ConstantVariables::KEY_PAIR_TYPE_EC
		];
		//Setup the domain_name to use
		$combinedDomainNameDot = $baseDomainName.'.'.$TLD;
		//If $subDommainName is not empty, then reset the combinedDomainNameDot
		if(!empty($subDomainName)) {
			$combinedDomainNameDot = $subDomainName.'.'.$baseDomainName.'.'.$TLD;
		}
		//Loop through for each order and execute
		foreach($order_list as $order_number) {
			$client = new ClientRequest($emailList, $sslDir.$combinedDomainNameUnderscore, $useStagingUrl);
			$domainInfo = [
				ConstantVariables::CHALLENGE_TYPE_HTTP => [
					$combinedDomainNameDot,
					((empty($subDomainName)) ? 'www.'.$combinedDomainNameDot : ''),
				],
			];
			try {
				//Try to get new order
				$order = $client->getOrder($domainInfo, $order_number);
			}
			catch(\Exception $e) {
				//Renewal is not ready yet
				break;
			}
			//Get challenge list
			$challengeList = $order->getPendingChallengeList();
			$path = $pathToWwwRoot.$combinedDomainNameDot.'/.well-known';
			if(file_exists($path)) {
				$this->rmdirRecursive($path);
			}
			//Make the path
			mkdir($path.DIRECTORY_SEPARATOR.'acme-challenge', 0777, true);
			//Keep track if it failed
			$failure_verify = false;
			/* Verify authorizations */
			foreach($challengeList as $challenge) {
				//Try catch block incase failure
				try {
					//Get the credentials
					$credential = $challenge->getCredential();
					//Put the contents on the server
					file_put_contents($path.DIRECTORY_SEPARATOR.'acme-challenge'.DIRECTORY_SEPARATOR.$credential['fileName'], $credential['fileContent']);
					/* Infinite loop until the authorization status becomes valid or 700 seconds has passed */
					$challenge->verify(700, 700);
				}
				catch(\Exception $e) {
					$failure_verify = true;
				}
			}
			if(file_exists($path)) {
				$this->rmdirRecursive($path);
			}
			//If verified, then get the certificates
			if(!$failure_verify) {
				//Retrieve certs
				$certificateInfo = $order->getCertificateFile();
				//Save to variables
				$private_key = file_get_contents($certificateInfo['privateKey']);
				$public_key = file_get_contents($certificateInfo['publicKey']);
				$certificate = file_get_contents($certificateInfo['certificate']);
				$certificateFullChained = file_get_contents($certificateInfo['certificateFullChained']);
				//Set the basename
				$base_name = $sslDir.$combinedDomainNameUnderscore.'/'.$combinedDomainNameUnderscore;
				//If order is KEY_PAIR_TYPE_EC, then append _ecc to the filename to differentiate it
				if($order_number == ConstantVariables::KEY_PAIR_TYPE_EC) {
					$base_name = $sslDir.$combinedDomainNameUnderscore.'/'.$combinedDomainNameUnderscore.'_ecc';
				}
				//Put on the server
				file_put_contents($base_name.'.key', $private_key);
				file_put_contents($base_name.'.pub', $public_key);
				file_put_contents($base_name.'.crt', $certificate);
				file_put_contents($base_name.'-fullchained.crt', $certificateFullChained);
			}
		}
	}

	/**
	 * Get ssl cert using DNS-01 as verification method for site ownership
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['test@test.com']
	 * @param $subDomainName:string ex: test
	 * @param $baseDomainName:string ex: test
	 * @param $TLD:string ex: com
	 * @param $godaddyCredentials:array ex: ['key' => 'xxxxxxxx', 'secret' => 'xxxxxxxxx']
	 * @param $renewCert:bool ex: FALSE
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function getSslCert_usingDns(
		string $sslDir = "",
		array $emailList = [],
		string $subDomainName = "",
		string $baseDomainName = "",
		string $TLD = 'com',
		array $godaddyCredentials = [],
		bool $renewCert = FALSE,
		bool $useStagingUrl = FALSE
	): void
	{
		//Setup the domain_name to use
		$combinedDomainNameUnderscore = $baseDomainName.'_'.$TLD;
		//If $subDommainName is not empty, then reset the combinedDomainNameUnderscore
		if(!empty($subDomainName)) {
			$combinedDomainNameUnderscore = $subDomainName.'_'.$baseDomainName.'_'.$TLD;
		}
		//If not renewing the cert, then remove old files
		if($renewCert == FALSE) {
			if(!file_exists($sslDir.$combinedDomainNameUnderscore)) {
				mkdir($sslDir.$combinedDomainNameUnderscore, 0755, false);
			}
			$files = scandir($sslDir.$combinedDomainNameUnderscore);
			$files = array_diff($files, array('.', '..'));
			foreach($files as $index => $dir_name) {
				if(is_dir($sslDir.$combinedDomainNameUnderscore.DIRECTORY_SEPARATOR.$dir_name) && $dir_name != "account") {
					$this->rmdirRecursive($sslDir.$combinedDomainNameUnderscore.DIRECTORY_SEPARATOR.$dir_name);
				}
			}
		}
		//Get both the RSA and EC keys
		$order_list = [
			ConstantVariables::KEY_PAIR_TYPE_RSA,
			ConstantVariables::KEY_PAIR_TYPE_EC
		];
		//Setup the domain_name to use
		$combinedDomainNameDot = $baseDomainName.'.'.$TLD;
		//If $subDommainName is not empty, then reset the combinedDomainNameDot
		if(!empty($subDomainName)) {
			$combinedDomainNameDot = $subDomainName.'.'.$baseDomainName.'.'.$TLD;
		}
		//Loop through for each order and execute
		foreach($order_list as $order_number) {
			$client = new ClientRequest($emailList, $sslDir.$combinedDomainNameUnderscore, $useStagingUrl);
			$domainInfo = [
				ConstantVariables::CHALLENGE_TYPE_DNS => [
					$combinedDomainNameDot,
					((empty($subDomainName)) ? '*.'.$combinedDomainNameDot : ''),
				],
			];
			try {
				//Try to get new order
				$order = $client->getOrder($domainInfo, $order_number);
			}
			catch(\Exception $e) {
				//Renewal is not ready yet
				break;
			}
			//Get challenge list
			$challengeList = $order->getPendingChallengeList();
			//Keep track if it failed
			$failure_verify = false;
			/* Verify authorizations */
			foreach($challengeList as $challenge) {
				//Try catch block incase failure
				try {
					//Get the credentials to push to DNS server
					$credential = $challenge->getCredential();
					//Put the contents up to the dns records
					$this->pushNewDnsRecord($combinedDomainNameDot, $credential, $godaddyCredentials);
					/* Infinite loop until the authorization status becomes valid or 700 seconds has passed */
					$challenge->verify(700, 700);
					//Delete the DNS records
					$this->deleteDnsRecord($combinedDomainNameDot, $godaddyCredentials);
				}
				catch(\Exception $e) {
					$failure_verify = true;
				}
			}
			//If verified, then get the certificates
			if(!$failure_verify) {
				//Retrieve certs
				$certificateInfo = $order->getCertificateFile();
				//Save to variables
				$private_key = file_get_contents($certificateInfo['privateKey']);
				$public_key = file_get_contents($certificateInfo['publicKey']);
				$certificate = file_get_contents($certificateInfo['certificate']);
				$certificateFullChained = file_get_contents($certificateInfo['certificateFullChained']);
				//Set the basename
				$base_name = $sslDir.$combinedDomainNameUnderscore.'/'.$combinedDomainNameUnderscore;
				//If order is KEY_PAIR_TYPE_EC, then append _ecc to the filename to differentiate it
				if($order_number == ConstantVariables::KEY_PAIR_TYPE_EC) {
					$base_name = $sslDir.$combinedDomainNameUnderscore.'/'.$combinedDomainNameUnderscore.'_ecc';
				}
				//Put on the server
				file_put_contents($base_name.'.key', $private_key);
				file_put_contents($base_name.'.pub', $public_key);
				file_put_contents($base_name.'.crt', $certificate);
				file_put_contents($base_name.'-fullchained.crt', $certificateFullChained);
			}
		}
	}

	/**
	 * Remove files and directories for given path
	 * @param $dir:string Ex: /var/www/ssl/test_com
	 * @return void
	 */
	private function rmdirRecursive(
		string $dir
	): void
	{
		foreach(scandir($dir) as $file) {
			if ('.' === $file || '..' === $file) continue;
			if (is_dir("$dir/$file")) $this->rmdirRecursive("$dir/$file");
			else unlink("$dir/$file");
		}
		rmdir($dir);
	}

	/**
	 * Push the record to Godaddy DNS
	 * @param $domain:string Ex: test.com
	 * @param $credential:array Ex: ['identifier' => 'test.com', 'dnsContent' => 'xxxxxxxxxxxxxxxxx']
	 * @param $godaddyCredentials:array Ex: ['key' => 'xxxxxxxx', 'secret' => 'xxxxxxxxx']
	 * @return void
	 */
	private function pushNewDnsRecord(
		string $domain,
		array $credential,
		array $godaddyCredentials
	): bool
	{
		//Prepare to push the dns record to godaddy
		$patch_body = [
			[
				'data' => $credential['dnsContent'],
				'name' => '_acme-challenge',
				'ttl' => 600,
				'type' => 'TXT'
			]
		];
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('PUT', 'https://api.godaddy.com/v1/domains/'.$domain.'/records/TXT/_acme-challenge', [
			'headers' => [
				'Accept' => 'application/json',
				'Content-Type' => 'application/json',
				'Authorization' => 'sso-key '.$godaddyCredentials['key'].':'.$godaddyCredentials['secret']
			],
			'body' => json_encode($patch_body),
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception('Failed with body: '.print_r($response->getBody()->__toString(), TRUE));
		}
		//Success
		return true;
	}

	/**
	 * Remove the record from Godaddy DNS
	 * @param $domain:string Ex: test.com
	 * @param $godaddyCredentials:array Ex: ['key' => 'xxxxxxxx', 'secret' => 'xxxxxxxxx']
	 * @return bool
	 */
	private function deleteDnsRecord(
		string $domain,
		array $godaddyCredentials
	): bool
	{
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('DELETE', 'https://api.godaddy.com/v1/domains/'.$domain.'/records/TXT/_acme-challenge', [
			'headers' => [
				'Accept' => 'application/json',
				'Content-Type' => 'application/json',
				'Authorization' => 'sso-key '.$godaddyCredentials['key'].':'.$godaddyCredentials['secret']
			],
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 204) {
			//Throw the Exception error
			throw new \Exception('Failed with body: '.print_r($response->getBody()->__toString(), TRUE));
		}
		//Success
		return true;
	}

	/**
	 * Update the contact email list on an existing Let's Encrypt account
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['new@example.com']
	 * @param $baseDomainName:string ex: example
	 * @param $TLD:string ex: com
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function updateAccountContact(
		string $sslDir = "",
		array $emailList = [],
		string $baseDomainName = "",
		string $TLD = 'com',
		bool $useStagingUrl = FALSE
	): void
	{
		//Setup the storage path for this account
		$combinedDomainNameUnderscore = $baseDomainName.'_'.$TLD;
		//Instantiate the client — this loads the existing account from disk
		$client = new ClientRequest($emailList, $sslDir.$combinedDomainNameUnderscore, $useStagingUrl);
		//Get the account service instance
		$account = $client->getAccount();
		try {
			//Update the contact email list on the ACME server
			$account->updateAccountContact($emailList);
		}
		catch(\Exception $e) {
			echo 'Failed to update account contact: '.$e->getMessage();
		}
	}

	/**
	 * Rotate the account private/public key pair
	 * The old key is replaced on both the ACME server and on disk.
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['alert@example.com']
	 * @param $baseDomainName:string ex: example
	 * @param $TLD:string ex: com
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function rotateAccountKey(
		string $sslDir = "",
		array $emailList = [],
		string $baseDomainName = "",
		string $TLD = 'com',
		bool $useStagingUrl = FALSE
	): void
	{
		//Setup the storage path for this account
		$combinedDomainNameUnderscore = $baseDomainName.'_'.$TLD;
		//Instantiate the client
		$client = new ClientRequest($emailList, $sslDir.$combinedDomainNameUnderscore, $useStagingUrl);
		//Get the account service instance
		$account = $client->getAccount();
		try {
			//Generate a new RSA key pair and register it with the ACME server
			//The old private.pem and public.pem on disk are replaced automatically
			$account->updateAccountKey();
		}
		catch(\Exception $e) {
			echo 'Failed to rotate account key: '.$e->getMessage();
		}
	}

	/**
	 * Deactivate a Let's Encrypt account permanently
	 * WARNING: This cannot be undone. All certificates issued under this account
	 * remain valid until expiry, but no new certificates can be issued.
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['alert@example.com']
	 * @param $baseDomainName:string ex: example
	 * @param $TLD:string ex: com
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function deactivateAccount(
		string $sslDir = "",
		array $emailList = [],
		string $baseDomainName = "",
		string $TLD = 'com',
		bool $useStagingUrl = FALSE
	): void
	{
		//Setup the storage path for this account
		$combinedDomainNameUnderscore = $baseDomainName.'_'.$TLD;
		//Instantiate the client
		$client = new ClientRequest($emailList, $sslDir.$combinedDomainNameUnderscore, $useStagingUrl);
		//Get the account service instance
		$account = $client->getAccount();
		try {
			//Permanently deactivate the account on the ACME server
			//The local private.pem and public.pem are deleted from disk automatically
			$account->deactivateAccount();
		}
		catch(\Exception $e) {
			echo 'Failed to deactivate account: '.$e->getMessage();
		}
	}
}
//Variables to use to get the SSL Certs
$sslDir = '/var/www/ssl/';
$hostsDir = '/var/www/hosts/';
$emailList = ['example@example.com'];
$subDomainName = 'dev';
$baseDomainName = 'example';
$TLD = 'com';
$godaddyCredentials = [
	'key' => '',
	'secret' => '',
];
$renewCert = FALSE;
$useStagingUrl = FALSE;
//Example declaration
$runClass = new Run();
$runClass->getSslCert_usingHttp(
	sslDir: $sslDir,
	emailList: $emailList,
	subDomainName: $subDomainName,
	baseDomainName: $baseDomainName,
	TLD: $TLD,
	pathToWwwRoot: $hostsDir,
	renewCert: $renewCert,
	useStagingUrl: $useStagingUrl
);
$runClass->getSslCert_usingDns(
	sslDir: $sslDir,
	emailList: $emailList,
	subDomainName: $subDomainName,
	baseDomainName: $baseDomainName,
	TLD: $TLD,
	godaddyCredentials: $godaddyCredentials,
	renewCert: $renewCert,
	useStagingUrl: $useStagingUrl
);
//Update the contact email list on the ACME account
$runClass->updateAccountContact(
	sslDir: $sslDir,
	emailList: $emailList,
	baseDomainName: $baseDomainName,
	TLD: $TLD,
	useStagingUrl: $useStagingUrl
);
//Rotate the account key pair (generates a new RSA key, registers it with ACME, replaces on disk)
$runClass->rotateAccountKey(
	sslDir: $sslDir,
	emailList: $emailList,
	baseDomainName: $baseDomainName,
	TLD: $TLD,
	useStagingUrl: $useStagingUrl
);
//Deactivate the account permanently — uncomment only when intentional
//$runClass->deactivateAccount(
//	sslDir: $sslDir,
//	emailList: $emailList,
//	baseDomainName: $baseDomainName,
//	TLD: $TLD,
//	useStagingUrl: $useStagingUrl
//);
