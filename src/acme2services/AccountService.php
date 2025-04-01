<?php
/**
 * AccountService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\acme2services;

use orangecam\acme2letsencrypt\helpers\CommonHelper;
use orangecam\acme2letsencrypt\helpers\OpenSSLHelper;
use orangecam\acme2letsencrypt\constants\ConstantVariables;
use orangecam\acme2letsencrypt\ClientRequest;
use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class AccountService
 * @package orangecam\acme2letsencrypt\acme2services
 */
class AccountService
{
	/**
	 * Hold RunRequest class instance
	 */
	private $runRequest;

	/**
	 * Account id
	 * @var string
	 */
	public $id;

	/**
	 * Account key
	 * @var array
	 */
	public $key;

	/**
	 * Account contact list
	 * @var array
	 */
	public $contact;

	/**
	 * Account agreement file url
	 * @var string
	 */
	public $agreement;

	/**
	 * Account initial ip
	 * @var string
	 */
	public $initialIp;

	/**
	 * Account creation time
	 * @var string
	 */
	public $createdAt;

	/**
	 * Account status
	 * @var string
	 */
	public $status;

	/**
	 * Access account info url
	 * @var string
	 */
	public $accountUrl;

	/**
	 * Private key storate path
	 * @var string
	 */
	private $_privateKeyPath;

	/**
	 * Public key storage path
	 * @var string
	 */
	private $_publicKeyPath;

	/**
	 * AccountService constructor.
	 * @param string $accountStoragePath
	 * @throws \Exception
	 */
	public function __construct(string $accountStoragePath)
	{
		//Check if storage path is not there, then create it if possible
		if(!is_dir($accountStoragePath) && mkdir($accountStoragePath, 0755, TRUE) === FALSE) {
			//Throw the Exception error
			throw new \Exception("create directory({$accountStoragePath}) failed, please check the permission.");
		}
		//Set the path for the private and public pem files for the account
		$this->_privateKeyPath = $accountStoragePath.'/private.pem';
		$this->_publicKeyPath = $accountStoragePath.'/public.pem';
	}

	/**
	 * Init
	 * @throws \Exception
	 */
	public function init()
	{
		//Check if the account keys exist, and if yes, then get the account
		if(is_file($this->_publicKeyPath) && is_file($this->_privateKeyPath)) {
			$this->getAccount();
			return;
		}
		//Else, delete the files
		@unlink($this->_privateKeyPath);
		@unlink($this->_publicKeyPath);
		//Attempt to create the account
		$this->createAccount();
	}

	/**
	 * Create new account
	 * @return array
	 * @throws \Exception
	 */
	private function createAccount()
	{
		//Create the key pair for the account
		$this->createKeyPairFile();
		//Contact list of emails
		$contactList = array_map(
			function($email) {
				return "mailto:{$email}";
			},
			ClientRequest::$runRequest->emailList
		);
		//Payload
		$payload = [
			'contact' => $contactList,
			'termsOfServiceAgreed' => TRUE,
		];
		//Merge payload
		$jws = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->newAccount,
			$payload
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', ClientRequest::$runRequest->endpoint->newAccount, [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 201) {
			//Throw the Exception error
			throw new \Exception("Create account failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the Replay-Nonce header
		$accountUrl = $response->getHeaderLine('Location');
		//If header does not exist, then throw an error
		if(empty($accountUrl)) {
			//Throw the Exception error
			throw new \Exception("Parse account url failed, the header is: {".print_r($response->getHeaders(), true)."}");
		}
		//Get the body
		try {
			$body = json_decode(trim($response->getBody()->__toString()), TRUE, 512, JSON_THROW_ON_ERROR);
		}
		catch(\JsonException $e) {
			$body = trim($response->getBody()->__toString());
		}
		//Merge the arrays
		$accountInfo = array_merge($body, ['accountUrl' => $accountUrl]);
		//Populate it in the class
		$this->populate($accountInfo);
		//Return
		return $accountInfo;
	}

	/**
	 * Get account info
	 * @return array
	 * @throws \Exception
	 */
	private function getAccount()
	{
		//Get the account
		$accountUrl = $this->getAccountUrl();
		//Prepare the body of the post request
		$jws = OpenSSLHelper::generateJWSOfKid(
			$accountUrl,
			$accountUrl,
			['' => '']
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', $accountUrl, [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Get account info failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the body
		try {
			$body = json_decode(trim($response->getBody()->__toString()), TRUE, 512, JSON_THROW_ON_ERROR);
		}
		catch(\JsonException $e) {
			$body = trim($response->getBody()->__toString());
		}
		//Populate
		$this->populate($body);
		//Return
		return array_merge($body, ['accountUrl' => $accountUrl]);
	}

	/**
	 * Get account url
	 * @return string
	 * @throws \Exception
	 */
	public function getAccountUrl()
	{
		//Return the accountUrl if already set
		if($this->accountUrl) {
			//Return
			return $this->accountUrl;
		}
		//Prepare the body of the post request
		$jws = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->newAccount,
			['onlyReturnExisting' => TRUE]
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', ClientRequest::$runRequest->endpoint->newAccount, [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Get account url failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the Location header
		$accountUrl = $response->getHeaderLine('Location');
		//If header does not exist, then throw an error
		if(empty($accountUrl)) {
			//Throw the Exception error
			throw new \Exception("The header doesn't contain `Location`, the url is: {$newNonceUrl}");
		}
		//Save the accountUrl
		$this->accountUrl = $accountUrl;
		//Return the accountUrl
		return $this->accountUrl;
	}

	/**
	 * Update account contact info
	 * @param array $emailList
	 * @return array
	 * @throws \Exception
	 */
	public function updateAccountContact(array $emailList)
	{
		//Get the accountUrl
		$accountUrl = $this->getAccountUrl();
		//Prepare contact list
		$contactList = array_map(
			function($email) {
				return "mailto:{$email}";
			},
			$emailList
		);
		//Prepare the body of the post request
		$jws = OpenSSLHelper::generateJWSOfKid(
			$accountUrl,
			$accountUrl,
			['contact' => $contactList]
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', $accountUrl, [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Update account contact info failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the body
		try {
			$body = json_decode(trim($response->getBody()->__toString()), TRUE, 512, JSON_THROW_ON_ERROR);
		}
		catch(\JsonException $e) {
			$body = trim($response->getBody()->__toString());
		}
		//Populate
		$this->populate($body);
		//Return
		return array_merge($body, ['accountUrl' => $accountUrl]);
	}

	/**
	 * Update accout private/public keys
	 * @throws \Exception
	 */
	public function updateAccountKey()
	{
		//Get a new keyPair
		$keyPair = OpenSSLHelper::generateKeyPair(ConstantVariables::KEY_PAIR_TYPE_RSA);
		//Get the details of it
		$privateKey = openssl_pkey_get_private($keyPair['privateKey']);
		$detail = openssl_pkey_get_details($privateKey);
		//Payload
		$innerPayload = [
			'account' => $this->getAccountUrl(),
			'newKey' => [
				'kty' => 'RSA',
				'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
				'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
			],
		];
		//More Payload
		$outerPayload = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->keyChange,
			$innerPayload,
			$keyPair['privateKey']
		);
		//More Payload
		$jws = OpenSSLHelper::generateJWSOfKid(
			ClientRequest::$runRequest->endpoint->keyChange,
			$this->getAccountUrl(),
			$outerPayload
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', ClientRequest::$runRequest->endpoint->keyChange, [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Update account key failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the body
		try {
			$body = json_decode(trim($response->getBody()->__toString()), TRUE, 512, JSON_THROW_ON_ERROR);
		}
		catch(\JsonException $e) {
			$body = trim($response->getBody()->__toString());
		}
		//Populate
		$this->populate($body);
		//KeyPair
		$this->createKeyPairFile($keyPair);
		//Return
		return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
	}

	/**
	 * Deactivate account
	 * @return array
	 * @throws \Exception
	 */
	public function deactivateAccount()
	{
		//Payload
		$jws = OpenSSLHelper::generateJWSOfKid(
			$this->getAccountUrl(),
			$this->getAccountUrl(),
			['status' => 'deactivated']
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('POST', $this->getAccountUrl(), [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jws
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Deactivate account failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the body
		try {
			$body = json_decode(trim($response->getBody()->__toString()), TRUE, 512, JSON_THROW_ON_ERROR);
		}
		catch(\JsonException $e) {
			$body = trim($response->getBody()->__toString());
		}
		//Populate
		$this->populate($body);
		//Remove the keys
		@unlink($this->_privateKeyPath);
		@unlink($this->_publicKeyPath);
		//Return
		return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
	}

	/**
	 * Get private key content
	 * @return bool|string
	 */
	public function getPrivateKey()
	{
		//Return path
		return file_get_contents($this->_privateKeyPath);
	}

	/**
	 * Create private/public key pair files
	 * @param array|null $keyPair
	 * @throws \Exception
	 */
	private function createKeyPairFile(array|null $keyPair = NULL)
	{
		//Generate the keyPair
		$keyPair = $keyPair ?: OpenSSLHelper::generateKeyPair(ConstantVariables::KEY_PAIR_TYPE_RSA);
		//Put the contents on the server
		$result = file_put_contents($this->_privateKeyPath, $keyPair['privateKey']) && file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);
		//Check if it was able to put the files on the server
		if($result === FALSE) {
			//Throw the Exception error
			throw new \Exception("Create account key pair files failed, the private key path is: {$this->_privateKeyPath}, the public key path is: {$this->_publicKeyPath}");
		}
	}

	/**
	 * Populate properties of instance
	 * @param array $accountInfo
	 */
	private function populate(array $accountInfo)
	{
		//Populate if property exists
		foreach($accountInfo as $key => $value) {
			//Check if the property_exists, then set the value
			if(property_exists($this, $key)) {
				//Set the value
				$this->{$key} = $value;
			}
		}
	}
}
