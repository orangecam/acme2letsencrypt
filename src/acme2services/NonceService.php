<?php
/**
 * NonceService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\acme2services;

use orangecam\acme2letsencrypt\ClientRequest;
use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class NonceService
 * @package orangecam\acme2letsencrypt\acme2services
 */
class NonceService
{
	/**
	 * Get new nonce for next request
	 * @return string
	 * @throws \Exception
	 */
	public function getNewNonce()
	{
		//Get the url from the runtime
		$newNonceUrl = ClientRequest::$runRequest->endpoint->newNonce;
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('HEAD', $newNonceUrl);
		//If acme2 endpoint is not responding, then throw an error
		if($response instanceof \GuzzleHttp\Psr7\Response && $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Get new nonce failed, the url is: {$newNonceUrl}");
		}
		//Get the Replay-Nonce header
		$replay_nonce_header = $response->getHeaderLine('Replay-Nonce');
		//If header does not exist, then throw an error
		if(empty($replay_nonce_header)) {
			throw new \Exception("Get new nonce failed, the header doesn't contain `Replay-Nonce`, the url is: {$newNonceUrl}");
		}
		//Return the nonce
		return $replay_nonce_header;
	}
}
