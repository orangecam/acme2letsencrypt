<?php
require 'vendor/autoload.php';

use orangecam\acme2letsencrypt\ClientRequest;
use orangecam\acme2letsencrypt\constants\ConstantVariables;
use GuzzleHttp\Client as GuzzleHttpClient;

class Run
{
	/**
	 * Get standard ssl cert using HTTP as verification method for site ownership
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['test@test.com']
	 * @param $name:string ex: test
	 * @param $topLevelDomain:string ex: com
	 * @param $pathToWwwRoot:string ex: /var/www/hosts/
	 * @param $renewCert:bool ex: FALSE
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	private function __getStandardSslCert_usingHttp(
		string $sslDir,
		array $emailList,
		string $name,
		string $topLevelDomain = 'com',
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
		//If not renewing the cert, then remove old files
		if($renewCert == FALSE) {
			if(!file_exists($sslDir.$name.'_'.$topLevelDomain)) {
				mkdir($sslDir.$name.'_'.$topLevelDomain, 0755, false);
			}
			$files = scandir($sslDir.$name.'_'.$topLevelDomain);
			$files = array_diff($files, array('.', '..'));
			foreach($files as $index => $dir_name) {
				if(is_dir($sslDir.$name.'_'.$topLevelDomain.DS.$dir_name) && $dir_name != "account") {
					$this->rmdirRecursive($sslDir.$name.'_'.$topLevelDomain.DS.$dir_name);
				}
			}
		}
		//Get both the RSA and EC keys
		$order_list = [
			CommonConstant::KEY_PAIR_TYPE_RSA,
			CommonConstant::KEY_PAIR_TYPE_EC
		];
		//Loop through for each order and execute
		foreach($order_list as $order_number) {
			$client = (new ClientRequest($emailList, $sslDir.$name.'_'.$topLevelDomain.'/', $useStagingUrl));
			$account = $client->getAccount();
			$domainInfo = [
				CommonConstant::CHALLENGE_TYPE_HTTP => [
					$name.'.'.$topLevelDomain,
					'www.'.$name.'.'.$topLevelDomain
				],
			];
			$order = $client->getOrder($domainInfo, $order_number);
			$challengeList = $order->getPendingChallengeList();
			$path = $pathToWwwRoot.$name.'.'.$topLevelDomain.'/.well-known';
			if(file_exists($path)) {
				$this->rmdirRecursive($path);
			}
			//Make the path
			mkdir($path.DS.'acme-challenge', 0777, true);
			//Keep track if it failed
			$failure_verify = false;
			/* Verify authorizations */
			foreach($challengeList as $challenge) {
				//Try catch block incase failure
				try {
					//Get the credentials
					$credential = $challenge->getCredential();
					//Put the contents on the server
					file_put_contents($path.DS.'acme-challenge'.DS.$credential['fileName'], $credential['fileContent']);
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
				$base_name = $sslDir.$name.'_'.$topLevelDomain.'/'.$name.'_'.$topLevelDomain;
				//If order is KEY_PAIR_TYPE_EC, then append _ecc to the filename to differentie it
				if($order_number == ConstantVariables::KEY_PAIR_TYPE_EC) {
					$base_name = $sslDir.$name.'_'.$topLevelDomain.'/'.$name.'_'.$topLevelDomain.'_ecc';
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
	 * Get standard ssl cert using DNS as verification method for site ownership
	 * @param $sslDir:string ex: /var/www/ssl
	 * @param $emailList:array ex: ['test@test.com']
	 * @param $name:string ex: test
	 * @param $topLevelDomain:string ex: com
	 * @param $godaddyCredentials:array ex: ['key' => 'xxxxxxxx', 'secret' => 'xxxxxxxxx']
	 * @param $renewCert:bool ex: FALSE
	 * @param $useStagingUrl:bool ex: FALSE
	 * @return void
	 */
	public function __getWilcardSslCert_usingDns(
		string $sslDir,
		array $emailList,
		string $name,
		string $topLevelDomain = 'com',
		array $godaddyCredentials = [],
		bool $renewCert = FALSE,
		bool $useStagingUrl = FALSE
	): void
	{
		//If not renewing the cert, then remove old files
		if($renewCert == FALSE) {
			if(!file_exists($sslDir.$name.'_'.$topLevelDomain)) {
				mkdir($sslDir.$name.'_'.$topLevelDomain, 0755, false);
			}
			$files = scandir($sslDir.$name.'_'.$topLevelDomain);
			$files = array_diff($files, array('.', '..'));
			foreach($files as $index => $dir_name) {
				if(is_dir($sslDir.$name.'_'.$topLevelDomain.DS.$dir_name) && $dir_name != "account") {
					$this->rmdirRecursive($sslDir.$name.'_'.$topLevelDomain.DS.$dir_name);
				}
			}
		}
		//Get both the RSA and EC keys
		$order_list = [
			CommonConstant::KEY_PAIR_TYPE_RSA,
			CommonConstant::KEY_PAIR_TYPE_EC
		];
		//Loop through for each order and execute
		foreach($order_list as $order_number) {
			$client = (new ClientRequest($emailList, $sslDir.$name.'_'.$topLevelDomain.'/', $useStagingUrl));
			$account = $client->getAccount();
			$domainInfo = [
				ConstantVariables::CHALLENGE_TYPE_DNS => [
					$name.'.'.$topLevelDomain,
					'*.'.$name.'.'.$topLevelDomain
				],
			];
			$order = $client->getOrder($domainInfo, $order_number);
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
					$this->pushNewDnsRecord($name.'.'.$topLevelDomain, $credential, $godaddyCredentials);
					/* Infinite loop until the authorization status becomes valid or 700 seconds has passed */
					$challenge->verify(700, 700);
				}
				catch(\Exception $e) {
					$failure_verify = true;
				}
			}
			//Delete the DNS records
			$this->deleteDnsRecord($name.'.'.$topLevelDomain, $godaddyCredentials);
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
				$base_name = $sslDir.$name.'_'.$topLevelDomain.'/'.$name.'_'.$topLevelDomain;
				//If order is KEY_PAIR_TYPE_EC, then append _ecc to the filename to differentie it
				if($order_number == ConstantVariables::KEY_PAIR_TYPE_EC) {
					$base_name = $sslDir.$name.'_'.$topLevelDomain.'/'.$name.'_'.$topLevelDomain.'_ecc';
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
}
//Variables to use to get the SSL Certs
$sslDir = '/var/www/ssl/';
$emailList = ['test@test.com'];
$name = 'test';
$topLevelDomain = 'com';
$godaddyCredentials = [
	'key' => '',
	'secret' => '',
];
//Example declaration
$runClass = new Run();
$runClass->__getStandardSslCert_usingHttp($sslDir, $emailList, $name, $topLevelDomain, '/var/www/hosts/', FALSE, FALSE);
$runClass->__getWilcardSslCert_usingDns($sslDir, $emailList, $name, $topLevelDomain, $godaddyCredentials, FALSE, FALSE);
