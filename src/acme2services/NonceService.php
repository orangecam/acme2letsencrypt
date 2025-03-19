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

use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class NonceService
 * @package orangecam\acme2letsencrypt\acme2services
 */
class NonceService
{
	/**
	 * Get new nonce for next request
	 * @param string nonceUrl
	 * @return string
	 * @throws NonceException
	 * @throws \orangecam\acme2letsencrypt\exceptions\RequestException
	 */
	public function getNewNonce(string $nonceUrl)
	{
		//Send the HEAD request and get the response
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the GET request, to make sure it is responding
		$response = $client->request('HEAD', $nonceUrl);
		//If acme2 endpoint is not responding, then throw an error
		if($response instanceof \GuzzleHttp\Psr7\Response && $response->getStatusCode() != 200) {
			//Throw the EndpointException error
			throw new NonceException("Get new nonce failed, the url is: {$newNonceUrl}");
		}
		//Get the Replay-Nonce header
		$replay_nonce_header = $response->getHeaderLine('Replay-Nonce');
		//Attempt to get the nonce header and return it
		if(empty($replay_nonce_header)) {
			throw new NonceException("Get new nonce failed, the header doesn't contain `Replay-Nonce`, the url is: {$newNonceUrl}");
		}
		//Return the nonce
		return $replay_nonce_header;
	}
}
