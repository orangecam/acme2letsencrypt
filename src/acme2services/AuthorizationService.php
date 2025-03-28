<?php
/**
 * AuthorizationService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\acme2services;

use orangecam\acme2letsencrypt\constants\ConstantVariables;
use orangecam\acme2letsencrypt\helpers\CommonHelper;
use orangecam\acme2letsencrypt\helpers\OpenSSLHelper;
use orangecam\acme2letsencrypt\ClientRequest;
use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class AuthorizationService
 * @package orangecam\acme2letsencrypt\acme2services
 */
class AuthorizationService
{
	/**
	 * Domain info
	 * @var array
	 */
	public $identifier;

	/**
	 * Authorization status: pending, valid, invalid
	 * @var string
	 */
	public $status;

	/**
	 * Expire time, like yyyy-mm-ddThh:mm:ssZ
	 * @var string
	 */
	public $expires;

	/**
	 * Supplied challenge types
	 * @var array
	 */
	public $challenges;

	/**
	 * Wildcard domain or not
	 * @var bool
	 */
	public $wildcard = FALSE;

	/**
	 * Initial domain name
	 * @var string
	 */
	public $domain;

	/**
	 * Access this url to get authorization info
	 * @var string
	 */
	public $authorizationUrl;

	/**
	 * AuthorizationService constructor.
	 * @param string $authorizationUrl
	 * @throws \Exception
	 */
	public function __construct(string $authorizationUrl)
	{
		//Set the variables as they are passed in
		$this->authorizationUrl = $authorizationUrl;
		//Get Authorization
		$this->getAuthorization();
	}

	/**
	 * Get authorization info
	 * @return array
	 * @throws \Exception
	 */
	public function getAuthorization()
	{
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('GET', $this->authorizationUrl);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Get authorization info failed, the authorization url is: {$this->authorizationUrl}, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//Get the body
		$body = json_decode(trim($response->getBody()->__toString()), TRUE);
		//Populate
		$this->populate($body);
		//Return
		return array_merge($body, ['authorizationUrl' => $this->authorizationUrl]);
	}

	/**
	 * Get challenge to verify
	 * @param string $type http-01 or dns-01
	 * @return mixed|null
	 */
	public function getChallenge(string $type)
	{
		//Get the challenges
		foreach($this->challenges as $challenge) {
			if($challenge['type'] == $type) {
				return $challenge;
			}
		}
		//No challenges, so nothing to do
		return NULL;
	}

	/**
	 * Make letsencrypt to verify
	 * @param string $type
	 * @param int $verifyLocallyTimeout
	 * @param int $verifyCATimeout
	 * @return bool
	 * @throws \Exception
	 */
	public function verify(string $type, int $verifyLocallyTimeout, int $verifyCATimeout)
	{
		//Get the Challenge for specific type
		$challenge = $this->getChallenge($type);
		//Check if status is pending
		if($this->status != 'pending' || $challenge['status'] != 'pending') {
			//Return
			return TRUE;
		}
		//Generate Thumbprint
		$keyAuthorization = $challenge['token'].'.'.OpenSSLHelper::generateThumbprint();
		//Verify
		$this->verifyLocally($type, $keyAuthorization, $verifyLocallyTimeout);
		//Prepare payload
		$jwk = OpenSSLHelper::generateJWSOfKid(
			$challenge['url'],
			ClientRequest::$runRequest->account->getAccountUrl(),
			['keyAuthorization' => $keyAuthorization]
		);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the GET request, to make sure it is responding
		$response = $client->request('POST', $challenge['url'], [
			'headers' => [
				'Accept' => 'application/jose+json',
				'Content-Type' => 'application/jose+json',
				'User-Agent' => ClientRequest::$runRequest->params['software'].'/'.ClientRequest::$runRequest->params['version'],
			],
			'body' => $jwk
		]);
		//If acme2 endpoint is not responding, then throw an error
		if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Send Request to letsencrypt to verify authorization failed, the url is: {".$challenge['url']."}, the domain is: {$this->identifier['value']}, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}, the body is: {".print_r($response->getBody()->__toString(), TRUE)."}");
		}
		//VerifyCA
		$this->verifyCA($type, $verifyCATimeout);
		//Return
		return TRUE;
	}

	/**
	 * Verify locally
	 * @param string $type
	 * @param string $keyAuthorization
	 * @param int $verifyLocallyTimeout
	 * @throws \Exception
	 */
	private function verifyLocally(string $type, string $keyAuthorization, int $verifyLocallyTimeout)
	{
		//Verify start time
		$verifyStartTime = time();
		//Loop until it passes, or time limt
		while(TRUE) {
			if($verifyLocallyTimeout > 0 && (time() - $verifyStartTime) > $verifyLocallyTimeout) {
				//Throw the Exception error
				throw new \Exception("Verify `{$this->domain}` via {$type} timeout, the timeout setting is: {$verifyLocallyTimeout} seconds");
			}

			$challenge = $this->getChallenge($type);
			$domain = $this->identifier['value'];

			if($type == ConstantVariables::CHALLENGE_TYPE_HTTP) {
				if(CommonHelper::checkHttpChallenge($domain, $challenge['token'], $keyAuthorization) === TRUE) {
					break;
				}
			}
			else {
				$dnsContent = CommonHelper::base64UrlSafeEncode(hash('sha256', $keyAuthorization, TRUE));

				if(CommonHelper::checkDNSChallenge($domain, $dnsContent) === TRUE) {
					break;
				}
			}

			sleep(3);
		}
	}

	/**
	 * Verify via Let's encrypt
	 * @param string $type
	 * @param int $verifyCATimeout
	 * @throws \Exception
	 */
	private function verifyCA(string $type, int $verifyCATimeout)
	{
		//Verify start time
		$verifyStartTime = time();
		//Loop until conditions
		while($this->status == 'pending') {
			if($verifyCATimeout > 0 && (time() - $verifyStartTime) > $verifyCATimeout) {
				//Throw the Exception error
				throw new \Exception("Verify `{$this->domain}` via {$type} timeout, the timeout setting is: {$verifyCATimeout} seconds");
			}

			sleep(3);

			$this->getAuthorization();
		}

		if($this->status != 'valid') {
			//Throw the Exception error
			throw new \Exception("Verify {$this->domain} via {$type} failed, the authorization status becomes {$this->status}.");
		}
	}

	/**
	 * Populate properties of this instance
	 * @param array $authorizationInfo
	 */
	private function populate(array $authorizationInfo)
	{
		//Populate if property exists
		foreach($authorizationInfo as $key => $value) {
			//Check if the property_exists, then set the value
			if(property_exists($this, $key)) {
				//Set the value
				$this->{$key} = $value;
			}
		}
		//Set the domain variable
		$this->domain = ($this->wildcard ? '*.' : '').$this->identifier['value'];
	}
}
