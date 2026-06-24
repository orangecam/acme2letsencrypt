<?php
/**
 * HttpClientService class file
 *
 * @author Cameron Brown <orangecam@msn.com>
 * @link https://github.com/orangecam/acme2letsencrypt
 * @copyright Copyright &copy; 2025 Cameron Brown
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\acme2services;

use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class HttpClientService
 *
 * Holds a single shared Guzzle client instance for the lifetime of a request.
 * Pass a config array to customise timeout, SSL verification, proxy, CA bundle, etc.
 * See https://docs.guzzlephp.org/en/stable/request-options.html for all options.
 *
 * Example config:
 *   ['timeout' => 30, 'verify' => '/path/to/ca-bundle.crt', 'proxy' => 'http://proxy:8080']
 *
 * @package orangecam\acme2letsencrypt\acme2services
 */
class HttpClientService
{
	/**
	 * Shared Guzzle client instance
	 * @var GuzzleHttpClient
	 */
	private $client;

	/**
	 * HttpClientService constructor.
	 * @param array $config Optional Guzzle client config (timeout, verify, proxy, etc.)
	 */
	public function __construct(array $config = [])
	{
		$this->client = new GuzzleHttpClient($config);
	}

	/**
	 * Get the shared Guzzle client
	 * @return GuzzleHttpClient
	 */
	public function getClient(): GuzzleHttpClient
	{
		return $this->client;
	}
}
