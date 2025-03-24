<?php
/**
 * CommonHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\helpers;

use GuzzleHttp\Client as GuzzleHttpClient;

/**
 * Class CommonHelper
 * @package orangecam\acme2letsencrypt\helpers
 */
class CommonHelper
{
	/**
	 * Base64 url safe encode
	 * @param string $string
	 * @return mixed
	 */
	public static function base64UrlSafeEncode($string)
	{
		return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
	}

	/**
	 * Get replay nonce from http response header
	 * @param string $header
	 * @return bool|string
	 */
	public static function getNonceFromResponseHeader($header)
	{
		return $this->getFieldFromHeader('Replay-Nonce', $header);
	}

	/**
	 * Get location field from http response header
	 * @param string $header
	 * @return bool|string
	 */
	public static function getLocationFieldFromHeader($header)
	{
		return $this->getFieldFromHeader('Location', $header);
	}

	/**
	 * Get field from http response header
	 * @param string $field
	 * @param string $header
	 * @return bool|string
	 */
	public static function getFieldFromHeader($field, $header)
	{
		//Check it
		if(!preg_match("/{$field}:\s*(\S+)/i", $header, $matches)){
			return FALSE;
		}
		//Return
		return trim($matches[1]);
	}

	/**
	 * Check http challenge locally, this challenge must be accomplished via http not https
	 * @param string $domain
	 * @param string $fileName
	 * @param string $fileContent
	 * @return bool
	 */
	public static function checkHttpChallenge($domain, $fileName, $fileContent)
	{
		//Setup the URL for use in the function
		$url = "http://{$domain}/.well-known/acme-challenge/{$fileName}";
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient();
		//Send the HEAD request and get the response
		$response = $client->request('GET', $url);
		//If acme2 endpoint is not responding, then throw an error
		if($response instanceof \GuzzleHttp\Psr7\Response && $response->getStatusCode() != 200) {
			//Throw the Exception error
			throw new \Exception("Get url failed, the file is not reachable at: {$url}");
		}
		//Get the body data from the GET request
		$body_data = $response->getBody()->__toString();
		//Check the body data against what is expected
		if($body_data == $fileContent) {
			//Success
			return TRUE;
		}
		//Failure
		return FALSE;
	}

	/**
	 * Check dns challenge locally
	 * @param string $domain
	 * @param string $dnsContent
	 * @return bool
	 */
	public static function checkDNSChallenge($domain, $dnsContent)
	{
		//Setup
		$host = '_acme-challenge.'.str_replace('*.', '', $domain);
		$recordList = @dns_get_record($host, DNS_TXT);
		//Check DNS record exists and is valid
		if(is_array($recordList)) {
			foreach($recordList as $record) {
				if($record['type'] == 'TXT' && $record['txt'] == $dnsContent) {
					//Success
					return TRUE;
				}
			}
		}
		//Failure
		return FALSE;
	}

	/**
	 * Get common name for csr generation
	 * @param array $domainList
	 * @return mixed
	 */
	public static function getCommonNameForCSR($domainList)
	{
		$domainLevel = [];

		foreach($domainList as $domain) {
			$domainLevel[count(explode('.', $domain))][] = $domain;
		}

		ksort($domainLevel);

		$shortestDomainList = reset($domainLevel);

		sort($shortestDomainList);

		return $shortestDomainList[0];
	}

	/**
	 * Get csr content without comment
	 * @param string $csr
	 * @return string
	 */
	public static function getCSRWithoutComment($csr)
	{
		//Setup
		$pattern = '/-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----/is';
		//Check it
		if(preg_match($pattern, $csr, $matches)) {
			return trim($matches[1]);
		}
		//return
		return $csr;
	}

	/**
	 * Get certificate content without comment
	 * @param string $certificate
	 * @return string
	 */
	public static function getCertificateWithoutComment($certificate)
	{
		//Setup
		$pattern = '/-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----/is';
		//Check it
		if(preg_match($pattern, $certificate, $matches)) {
			return trim($matches[1]);
		}
		//return
		return $certificate;
	}

	/**
	 * Extract certificate from server response
	 * @param string $certificateFromServer
	 * @return array|null
	 */
	public static function extractCertificate($certificateFromServer)
	{
		//Setup
		$certificate = '';
		$certificateFullChained = '';
		$pattern = '/-----BEGIN\sCERTIFICATE-----(.*?)-----END\sCERTIFICATE-----/is';
		//If valid and matches, then output the certificates
		if(preg_match_all($pattern, $certificateFromServer, $matches)) {
			$certificate = trim($matches[0][0]);
			foreach($matches[0] as $match) {
				$certificateFullChained .= trim($match)."\n";
			}
			return [
				'certificate' => $certificate,
				'certificateFullChained' => trim($certificateFullChained),
			];
		}
		//Failure
		return NULL;
	}
}
