<?php
/**
 * OrderService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\services;

use orangecam\acme2letsencrypt\constants\ConstantVariables;
use orangecam\acme2letsencrypt\helpers\CommonHelper;
use orangecam\acme2letsencrypt\helpers\OpenSSLHelper;

/**
 * Class OrderService
 * @package orangecam\acme2letsencrypt\services
 */
class OrderService
{
	/**
	 * Helper classes
	 */
	private $common;
	private $openssl;

	/**
	 * Order status: pending, processing, valid, invalid
	 * @var string
	 */
	public $status;

	/**
	 * Order expire time
	 * @var string
	 */
	public $expires;

	/**
	 * Domains info
	 * @var array
	 */
	public $identifiers;

	/**
	 * Domain authorization info
	 * @var array
	 */
	public $authorizations;

	/**
	 * Finalize order url
	 * @var string
	 */
	public $finalize;

	/**
	 * Fetch certificate content url
	 * @var string
	 */
	public $certificate;

	/**
	 * Order info url
	 * @var string
	 */
	public $orderUrl;

	/**
	 * Order AuthorizationService instance list
	 * @var AuthorizationService[]
	 */
	private $_authorizationList;

	/**
	 * Domain list
	 * @var array
	 */
	private $_domainList;

	/**
	 * Domain challenge type info
	 * @var array
	 */
	private $_domainChallengeTypeMap;

	/**
	 * Certificate encrypt type
	 * @var int
	 */
	private $_algorithm;

	/**
	 * Whether to generate a new order or not. When `true` the existing files will be removed.
	 * @var bool
	 */
	private $_generateNewOrder;

	/**
	 * Certificate private key file path
	 * @var string
	 */
	private $_privateKeyPath;

	/**
	 * Certificate public key file path
	 * @var string
	 */
	private $_publicKeyPath;

	/**
	 * Certificate csr file storage path
	 * @var string
	 */
	private $_csrPath;

	/**
	 * Certificate storage file path
	 * @var string
	 */
	private $_certificatePath;

	/**
	 * Certificate full-chained file storage path
	 * @var string
	 */
	private $_certificateFullChainedPath;

	/**
	 * Order info file storage path
	 * @var string
	 */
	private $_orderInfoPath;

	/**
	 * OrderService constructor.
	 * OrderService constructor.
	 * @param array $domainInfo
	 * @param int $algorithm
	 * @param bool $generateNewOder
	 * @throws \Exception
	 */
	public function __construct(array $domainInfo, int $algorithm, bool $generateNewOder)
	{
		$this->_algorithm = $algorithm;
		$this->_generateNewOrder = boolval($generateNewOder);

		foreach($domainInfo as $challengeType => $domainList) {
			foreach($domainList as $domain) {
				$domain = trim($domain);

				$this->_domainList[] = $domain;
				$this->_domainChallengeTypeMap[$domain] = $challengeType;
			}
		}

		$this->_domainList = array_unique($this->_domainList);

		sort($this->_domainList);

		$this->init();
	}

	/**
	 * Initialization
	 * @throws \Exception
	 */
	public function init()
	{
		$flag = substr(md5(implode(',', $this->_domainList)), 11, 8);

		$algorithmNameMap = [
			ConstantVariables::KEY_PAIR_TYPE_RSA => 'rsa',
			ConstantVariables::KEY_PAIR_TYPE_EC => 'ec',
		];

		$algorithmName = $algorithmNameMap[$this->_algorithm];
		$basePath = Client::$runtime->storagePath.DIRECTORY_SEPARATOR.$flag.DIRECTORY_SEPARATOR.$algorithmName;

		if(!is_dir($basePath)) {
			mkdir($basePath, 0755, TRUE);
		}

		$pathMap = [
			'_privateKeyPath' => 'private.pem',
			'_publicKeyPath' => 'public.pem',
			'_csrPath' => 'certificate.csr',
			'_certificatePath' => 'certificate.crt',
			'_certificateFullChainedPath' => 'certificate-fullchained.crt',
			'_orderInfoPath' => 'ORDER',
		];

		foreach($pathMap as $propertyName => $fileName) {
			$this->{$propertyName} = $basePath.DIRECTORY_SEPARATOR.$fileName;
		}

		if($this->_generateNewOrder === TRUE) {
			foreach($pathMap as $propertyName => $fileName) {
				@unlink($basePath.DIRECTORY_SEPARATOR.$fileName);
			}
		}

		if($this->_generateNewOrder === TRUE) {
			$this->createOrder();
		}
		else {
			$this->getOrder();
		}

		file_put_contents(
			Client::$runtime->storagePath.DIRECTORY_SEPARATOR.$flag.DIRECTORY_SEPARATOR.'DOMAIN',
			implode("\r\n", $this->_domainList)
		);
	}

	/**
	 * Create new order
	 * @return array
	 * @throws \Exception
	 */
	private function createOrder()
	{
		$identifierList = [];

		foreach($this->_domainList as $domain)
		{
			$identifierList[] = [
				'type' => 'dns',
				'value' => $domain,
			];
		}

		$payload = [
			'identifiers' => $identifierList,
			'notBefore' => '',
			'notAfter' => '',
		];

		$jws = OpenSSLHelper::generateJWSOfKid(
			Client::$runtime->endpoint->newOrder,
			Client::$runtime->account->getAccountUrl(),
			$payload
		);

		list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->newOrder, $jws);

		if($code != 201)
		{
			throw new \Exception('Create order failed, the domain list is: '.implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		if(($orderUrl = CommonHelper::getLocationFieldFromHeader($header)) === FALSE)
		{
			throw new \Exception('Get order url failed during order creation, the domain list is: '.implode(', ', $this->_domainList));
		}

		$orderInfo = array_merge($body, ['orderUrl' => $orderUrl]);

		$this->populate($orderInfo);
		$this->setOrderInfoToCache(['orderUrl' => $orderUrl]);
		$this->getAuthorizationList();

		return $orderInfo;
	}

	/**
	 * Get an existed order info
	 * @param bool $getAuthorizationList
	 * @return array
	 * @throws \Exception
	 */
	private function getOrder($getAuthorizationList = TRUE)
	{
		if(!is_file($this->_orderInfoPath))
		{
			throw new \Exception("Get order info failed, the local order info file doesn't exist, the order info file path is: {$this->_orderInfoPath}");
		}

		$orderUrl = $this->getOrderInfoFromCache()['orderUrl'];

		list($code, $header, $body) = RequestHelper::get($orderUrl);

		if($code != 200)
		{
			throw new \Exception("Get order info failed, the order url is: {$orderUrl}, the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate(array_merge($body, ['orderUrl' => $orderUrl]));

		if($getAuthorizationList === TRUE)
		{
			$this->getAuthorizationList();
		}

		return array_merge($body, ['orderUrl' => $orderUrl]);
	}

	/**
	 * Get pending challenges info
	 * @return ChallengeService[]
	 */
	public function getPendingChallengeList()
	{
		if($this->isAllAuthorizationValid() === TRUE)
		{
			return [];
		}

		$challengeList = [];
		$thumbprint = OpenSSLHelper::generateThumbprint();

		foreach($this->_authorizationList as $authorization)
		{
			if($authorization->status != 'pending')
			{
				continue;
			}

			$challengeType = $this->_domainChallengeTypeMap[$authorization->domain];
			$challenge = $authorization->getChallenge($challengeType);

			if($challenge['status'] != 'pending')
			{
				continue;
			}

			$challengeContent = $challenge['token'].'.'.$thumbprint;
			$challengeService = new ChallengeService($challengeType, $authorization);

			/* Generate challenge info for http-01 */
			if($challengeType == ConstantVariables::CHALLENGE_TYPE_HTTP)
			{
				$challengeCredential = [
					'identifier' => $authorization->identifier['value'],
					'fileName' => $challenge['token'],
					'fileContent' => $challengeContent,
				];
			}

			/* Generate challenge info for dns-01 */
			else
			{
				$challengeCredential = [
					'identifier' => $authorization->identifier['value'],
					'dnsContent' => CommonHelper::base64UrlSafeEncode(hash('sha256', $challengeContent, TRUE)),
				];
			}

			$challengeService->setCredential($challengeCredential);

			$challengeList[] = $challengeService;
		}

		return $challengeList;
	}

	/**
	 * Get certificate file path info after verifying
	 * @param string|null $csr
	 * @return array
	 * @throws \Exception
	 */
	public function getCertificateFile($csr = NULL)
	{
		if($this->isAllAuthorizationValid() === FALSE)
		{
			throw new \Exception("There are still some authorizations that are not valid.");
		}

		$this->waitStatus('ready');
		$this->finalizeOrder(CommonHelper::getCSRWithoutComment($csr ?: $this->getCSR()));
		$this->waitStatus('valid');

		list($code, $header, $body) = RequestHelper::get($this->certificate);

		if($code != 200)
		{
			throw new \Exception("Fetch certificate from letsencrypt failed, the url is: {$this->certificate}, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$certificateMap = CommonHelper::extractCertificate($body);

		file_put_contents($this->_certificatePath, $certificateMap['certificate']);
		file_put_contents($this->_certificateFullChainedPath, $certificateMap['certificateFullChained']);

		$certificateInfo = openssl_x509_parse($certificateMap['certificate']);

		$this->setOrderInfoToCache([
			'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
			'validToTimestamp' => $certificateInfo['validTo_time_t'],
			'validFromTime' => date('Y-m-d H:i:s', $certificateInfo['validFrom_time_t']),
			'validToTime' => date('Y-m-d H:i:s', $certificateInfo['validTo_time_t']),
		]);

		return [
			'privateKey' => realpath($this->_privateKeyPath),
			'publicKey' => realpath($this->_publicKeyPath),
			'certificate' => realpath($this->_certificatePath),
			'certificateFullChained' => realpath($this->_certificateFullChainedPath),
			'validFromTimestamp' => $certificateInfo['validFrom_time_t'],
			'validToTimestamp' => $certificateInfo['validTo_time_t'],
		];
	}

	/**
	 * Revoke certificate
	 * @param int $reason you can find the code in `https://tools.ietf.org/html/rfc5280#section-5.3.1`
	 * @return bool
	 * @throws \Exception
	 */
	public function revokeCertificate($reason = 0)
	{
		if($this->status != 'valid')
		{
			throw new \Exception("Revoke certificate failed because of invalid status({$this->status})");
		}

		if(!is_file($this->_certificatePath))
		{
			throw new \Exception("Revoke certificate failed because of certicate file missing({$this->_certificatePath})");
		}

		$certificate = CommonHelper::getCertificateWithoutComment(file_get_contents($this->_certificatePath));
		$certificate = trim(CommonHelper::base64UrlSafeEncode(base64_decode($certificate)));

		$jws = OpenSSLHelper::generateJWSOfJWK(
			Client::$runtime->endpoint->revokeCert,
			[
				'certificate' => $certificate,
				'reason' => $reason,
			],
			$this->getPrivateKey()
		);

		list($code, $header, $body) = RequestHelper::post(Client::$runtime->endpoint->revokeCert, $jws);

		if($code != 200)
		{
			throw new \Exception("Revoke certificate failed, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		return TRUE;
	}

	/**
	 * Check weather all authorization is valid, if yes, it means all the challenges had passed
	 * @return bool
	 */
	public function isAllAuthorizationValid()
	{
		foreach($this->_authorizationList as $authorization) {
			if($authorization->status != 'valid') {
				return FALSE;
			}
		}

		return TRUE;
	}

	/**
	 * Check weather order had been finalized
	 * @return bool
	 */
	public function isOrderFinalized()
	{
		return ($this->status == 'processing' || $this->status == 'valid');
	}

	/**
	 * Finalize order to get certificate
	 * @param string $csr
	 * @throws \Exception
	 */
	private function finalizeOrder($csr)
	{
		$jws = OpenSSLHelper::generateJWSOfKid(
			$this->finalize,
			Client::$runtime->account->getAccountUrl(),
			['csr' => trim(CommonHelper::base64UrlSafeEncode(base64_decode($csr)))]
		);

		list($code, $header, $body) = RequestHelper::post($this->finalize, $jws);

		if($code != 200) {
			throw new \Exception("Finalize order failed, the url is: {$this->finalize}, the domain list is: ".implode(', ', $this->_domainList).", the code is: {$code}, the header is: {$header}, the body is: ".print_r($body, TRUE));
		}

		$this->populate($body);
		$this->getAuthorizationList();
	}

	/**
	 * Generate authorization instances according to order info
	 */
	private function getAuthorizationList()
	{
		$this->_authorizationList = [];

		foreach($this->authorizations as $authorizationUrl) {
			$authorization = new AuthorizationService($authorizationUrl);

			$this->_authorizationList[] = $authorization;
		}
	}

	/**
	 * Get csr info, if the csr doesn't exist then create it
	 * @return bool|string
	 */
	private function getCSR()
	{
		if(!is_file($this->_csrPath)) {
			$this->createCSRFile();
		}

		return file_get_contents($this->_csrPath);
	}

	/**
	 * Create csr file
	 */
	private function createCSRFile()
	{
		$domainList = array_map(
			function($identifier) {
				return $identifier['value'];
			},
			$this->identifiers
		);

		$csr = OpenSSLHelper::generateCSR(
			$domainList,
			['commonName' => CommonHelper::getCommonNameForCSR($domainList)],
			$this->getPrivateKey()
		);

		file_put_contents($this->_csrPath, $csr);
	}

	/**
	 * Get private key info, if private/public key files doesn't exist then create them
	 * @return bool|string
	 * @throws \Exception
	 */
	private function getPrivateKey()
	{
		if(!is_file($this->_privateKeyPath) || !is_file($this->_publicKeyPath)) {
			$this->createKeyPairFile();
		}

		return file_get_contents($this->_privateKeyPath);
	}

	/**
	 * Create private/public key files
	 * @throws \Exception
	 */
	private function createKeyPairFile()
	{
		$keyPair = OpenSSLHelper::generateKeyPair($this->_algorithm);

		$result = file_put_contents($this->_privateKeyPath, $keyPair['privateKey']) && file_put_contents($this->_publicKeyPath, $keyPair['publicKey']);

		if($result === FALSE) {
			throw new \Exception('Create order key pair files failed, the domain list is: '.implode(', ', $this->_domainList).", the private key path is: {$this->_privateKeyPath}, the public key path is: {$this->_publicKeyPath}");
		}
	}

	/**
	 * Get order basic info from file cache
	 * @return array
	 */
	private function getOrderInfoFromCache()
	{
		$orderInfo = [];

		if(is_file($this->_orderInfoPath)) {
			$orderInfo = json_decode(file_get_contents($this->_orderInfoPath), TRUE);
		}

		return $orderInfo ?: [];
	}

	/**
	 * Set order basic info to file cache
	 * @param array $orderInfo
	 * @return bool|int
	 */
	private function setOrderInfoToCache($orderInfo)
	{
		$orderInfo = array_merge($this->getOrderInfoFromCache(), $orderInfo);

		return file_put_contents($this->_orderInfoPath, json_encode($orderInfo));
	}

	/**
	 * 等待订单状态
	 * @param $staus
	 * @throws \Exception
	 */
	private function waitStatus($staus)
	{
		while($this->status != $staus) {
			sleep(3);

			$this->getOrder(FALSE);
		}
	}

	/**
	 * Populate properties of this instance
	 * @param array $orderInfo
	 */
	private function populate($orderInfo)
	{
		//Populate if property exists
		foreach($orderInfo as $key => $value) {
			//Check if the property_exists, then set the value
			if(property_exists($this, $key)) {
				//Set the value
				$this->{$key} = $value;
			}
		}
	}
}
