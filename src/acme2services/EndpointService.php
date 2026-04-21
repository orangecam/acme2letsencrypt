<?php
/**
 * EndpointService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\acme2services;

use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class EndpointService
 * @package orangecam\acme2letsencrypt\acme2services
 */
class EndpointService
{
	/**
	 * Endpoint production environment url
	 */
	private $endpointUrl = 'https://acme-v02.api.letsencrypt.org/directory';

	/**
	 * Endpoint test environment url
	 */
	private $endpointStagingUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';

	/**
	 * Change account key url
	 * @var string
	 */
	public $keyChange;

	/**
	 * Create new account url
	 * @var string
	 */
	public $newAccount;

	/**
	 * Generate new nonce url
	 * @var string
	 */
	public $newNonce;

	/**
	 * Create new order url
	 * @var string
	 */
	public $newOrder;

	/**
	 * Renewal info url
	 * @var string
	 */
	public $renewalInfo;

	/**
	 * Revoke certificate url
	 * @var string
	 */
	public $revokeCert;

	/**
	 * EndpointService constructor
	 * @param bool $staging
	 * @throws \Exception
	 */
	public function __construct(bool $staging)
	{
		$this->populate($staging);
	}

	/**
	 * Populate endpoint info
	 * @throws \Exception
	 */
	private function populate(bool $staging)
	{
		//Which endpoint to use
		$acme2EndpointUrl = ((empty($staging)) ? $this->endpointUrl : $this->endpointStagingUrl);
		//Try catch
		try {
			//Setup the GuzzleHttpClient
			$client = new GuzzleHttpClient();
			//Send the GET request, to make sure it is responding
			$response = $client->request('GET', $acme2EndpointUrl);
			//Check if status code is successful
			if($response->getStatusCode() !== 200) {
				//Throw the Exception error
				throw new \Exception("Get failed, the code is: {$response->getStatusCode()}, the headers are: {".print_r($response->getHeaders(), true)."}");
			}
			//Check if the response content type is JSON
			$contentType = $response->getHeaderLine('Content-Type');
			//Check to make sure application/json is returned
			if(strpos($contentType, 'application/json') === false) {
				//Throw the Exception error
				throw new \Exception("The response is not JSON, the url is: {".$acme2EndpointUrl."}");
			}
			//Get the body
			$body = json_decode(trim($response->getBody()->getContents()), true, 512, JSON_THROW_ON_ERROR);
		}
		catch(\GuzzleHttp\Exception\GuzzleException $e) {
			//Handle connection or client errors
			throw new \Exception("Error: ".$e->getMessage());
		}
		//Populate if property exists
		foreach($body as $key => $value) {
			//Check if the property_exists, then set the value
			if(property_exists($this, $key)) {
				//Set the value
				$this->{$key} = $value;
			}
		}
	}
}
