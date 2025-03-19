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
	 * Revoke certificate url
	 * @var string
	 */
	public $revokeCert;

	/**
	 * EndpointService constructor
	 * @param bool $staging
	 * @throws EndpointException
	 * @throws \orangecam\acme2letsencrypt\exceptions\RequestException
	 */
	public function __construct(bool $staging)
	{
		$this->populate($staging);
	}

	/**
	 * Populate endpoint info
	 * @throws EndpointException
	 * @throws \orangecam\acme2letsencrypt\exceptions\RequestException
	 */
	private function populate(bool $staging)
	{
		//Which endpoint to use
		$acme2EndpointUrl = ((empty($staging)) ? $this->endpointUrl : $this->endpointStagingUrl);
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the GET request, to make sure it is responding
		$response = $client->request('GET', $acme2EndpointUrl);
		//If acme2 endpoint is not responding, then throw an error
		if($response instanceof \GuzzleHttp\Psr7\Response && $response->getStatusCode() != 200) {
			//Throw the EndpointException error
			throw new EndpointException("Get endpoint info failed, the url is: {$acme2EndpointUrl}");
		}
		//Get the body
		if(!empty(strpos($response->getHeaderLine('Content-Type'), 'application/json'))) {
			//Throw the EndpointException error
			throw new EndpointException("The body from the get endpoint is not valid, the url is: {$acme2EndpointUrl}");
		}
		$data = json_decode($response->getBody()->__toString(), true);
		//Update the variable in the class
		foreach($data as $key => $value) {
			//Check if the property_exists, then set the value
			if(property_exists($this, $key)) {
				//Set the value
				$this->{$key} = $value;
			}
		}
	}
}
