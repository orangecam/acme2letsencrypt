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
	 * @param $accountStoragePath
	 * @throws \Exception
	 */
	public function __construct($accountStoragePath)
	{
		//Check if storage path is not there, then create it if possible
		if(!is_dir($accountStoragePath) && mkdir($accountStoragePath, 0755, TRUE) === FALSE) {
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
		$this->createKeyPairFile();

		$contactList = array_map(
			function($email) {
				return "mailto:{$email}";
			},
			ClientRequest::$runRequest->emailList
		);

		$payload = [
			'contact' => $contactList,
			'termsOfServiceAgreed' => TRUE,
		];

		$jws = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->newAccount,
			$payload
		);

		list($code, $header, $body) = RequestHelper::post(ClientRequest::$runRequest->endpoint->newAccount, $jws);

		if($code != 201) {
			throw new \Exception("Create account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		if(!($accountUrl = CommonHelper::getLocationFieldFromHeader($header))) {
			throw new \Exception("Parse account url failed, the header is: {$header}");
		}

		$accountInfo = array_merge($body, ['accountUrl' => $accountUrl]);

		$this->populate($accountInfo);

		return $accountInfo;
	}

	/**
	 * Get account info
	 * @return array
	 * @throws \Exception
	 */
	private function getAccount()
	{
		$accountUrl = $this->getAccountUrl();

		$jws = OpenSSLHelper::generateJWSOfKid(
			$accountUrl,
			$accountUrl,
			['' => '']
		);

		list($code, $header, $body) = RequestHelper::post($accountUrl, $jws);

		if($code != 200) {
			throw new \Exception("Get account info failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate($body);

		return array_merge($body, ['accountUrl' => $accountUrl]);
	}

	/**
	 * Get account url
	 * @return string
	 * @throws \Exception
	 */
	public function getAccountUrl()
	{
		if($this->accountUrl) {
			return $this->accountUrl;
		}

		$jws = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->newAccount,
			['onlyReturnExisting' => TRUE]
		);

		list($code, $header, $body) = RequestHelper::post(ClientRequest::$runRequest->endpoint->newAccount, $jws);

		if($code != 200) {
			throw new \Exception("Get account url failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		if(!($accountUrl = CommonHelper::getLocationFieldFromHeader($header))) {
			throw new \Exception("Parse account url failed, the header is: {$header}");
		}

		$this->accountUrl = $accountUrl;

		return $this->accountUrl;
	}

	/**
	 * Update account contact info
	 * @param $emailList
	 * @return array
	 * @throws \Exception
	 */
	public function updateAccountContact($emailList)
	{
		$accountUrl = $this->getAccountUrl();

		$contactList = array_map(
			function($email) {
				return "mailto:{$email}";
			},
			$emailList
		);

		$jws = OpenSSLHelper::generateJWSOfKid(
			$accountUrl,
			$accountUrl,
			['contact' => $contactList]
		);

		list($code, $header, $body) = RequestHelper::post($accountUrl, $jws);

		if($code != 200) {
			throw new \Exception("Update account contact info failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate($body);

		return array_merge($body, ['accountUrl' => $accountUrl]);
	}

	/**
	 * Update accout private/public keys
	 * @throws \Exception
	 */
	public function updateAccountKey()
	{
		$keyPair = OpenSSLHelper::generateKeyPair(ConstantVariables::KEY_PAIR_TYPE_RSA);

		$privateKey = openssl_pkey_get_private($keyPair['privateKey']);
		$detail = openssl_pkey_get_details($privateKey);

		$innerPayload = [
			'account' => $this->getAccountUrl(),
			'newKey' => [
				'kty' => 'RSA',
				'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
				'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
			],
		];

		$outerPayload = OpenSSLHelper::generateJWSOfJWK(
			ClientRequest::$runRequest->endpoint->keyChange,
			$innerPayload,
			$keyPair['privateKey']
		);

		$jws = OpenSSLHelper::generateJWSOfKid(
			ClientRequest::$runRequest->endpoint->keyChange,
			$this->getAccountUrl(),
			$outerPayload
		);

		list($code, $header, $body) = RequestHelper::post(ClientRequest::$runRequest->endpoint->keyChange, $jws);

		if($code != 200) {
			throw new \Exception("Update account key failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate($body);
		$this->createKeyPairFile($keyPair);

		return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
	}

	/**
	 * Deactivate account
	 * @return array
	 * @throws \Exception
	 */
	public function deactivateAccount()
	{
		$jws = OpenSSLHelper::generateJWSOfKid(
			$this->getAccountUrl(),
			$this->getAccountUrl(),
			['status' => 'deactivated']
		);

		list($code, $header, $body) = RequestHelper::post($this->getAccountUrl(), $jws);

		if($code != 200) {
			throw new \Exception("Deactivate account failed, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate($body);

		@unlink($this->_privateKeyPath);
		@unlink($this->_publicKeyPath);

		return array_merge($body, ['accountUrl' => $this->getAccountUrl()]);
	}

	/**
	 * Get private key content
	 * @return bool|string
	 */
	public function getPrivateKey()
	{
		return file_get_contents($this->_privateKeyPath);
	}

	/**
	 * Create private/public key pair files
	 * @param array|null $keyPair
	 * @throws \Exception
	 */
	private function createKeyPairFile($keyPair = NULL)
	{
		$keyPair = $keyPair ?: OpenSSLHelper::generateKeyPair(ConstantVariables::KEY_PAIR_TYPE_RSA);

		$result = file_put_contents($this->_privateKeyPath, $keyPair['privateKey']) && file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);

		if($result === FALSE) {
			throw new \Exception("Create account key pair files failed, the private key path is: {$this->_privateKeyPath}, the public key path is: {$this->_publicKeyPath}");
		}
	}

	/**
	 * Populate properties of instance
	 * @param array $accountInfo
	 */
	private function populate($accountInfo)
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
