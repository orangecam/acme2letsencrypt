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
	public static function base64UrlSafeEncode(string $string)
	{
		return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
	}

	/**
	 * Check http challenge locally, this challenge must be accomplished via http not https
	 * @param string $domain
	 * @param string $fileName
	 * @param string $fileContent
	 * @return bool
	 */
	public static function checkHttpChallenge(string $domain, string $fileName, string $fileContent)
	{
		//Setup the URL for use in the function
		$url = "http://{$domain}/.well-known/acme-challenge/{$fileName}";
		//Setup the GuzzleHttpClient
		$client = new GuzzleHttpClient(['timeout' => 10, 'verify' => false]);
		//try catch block
		try {
			//Send the GET request and get the response
			$response = $client->request('GET', $url);
			//If acme2 endpoint is not responding, then throw an error
			if(!($response instanceof \GuzzleHttp\Psr7\Response) || $response->getStatusCode() !== 200) {
				return false;
			}
			//Get the body
			$body = trim((string)$response->getBody());
			//Handle case where server returns JSON or plain text
			if(strpos($body, '{') === 0) {
				$decoded = json_decode($body, true);
				$body = is_array($decoded) ? ($decoded['content'] ?? $body) : $body;
			}
			//Return the body data against what is expected
			return $body === $fileContent;
		}
		catch(\Exception $e) {
			// Log or handle: Connection refused, DNS failure, etc.
			return false;
		}
	}

	/**
	 * Check dns challenge locally
	 * @param string $domain
	 * @param string $dnsContent
	 * @return bool
	 */
	public static function checkDNSChallenge(string $domain, string $dnsContent)
	{
		//Setup host string for query
		$host = '_acme-challenge.' . ltrim($domain, '*.');
		//Try PHP internal check
		$recordList = @dns_get_record($host, DNS_TXT);
		if(is_array($recordList)) {
			foreach($recordList as $record) {
				if(trim($record['txt'] ?? '', '" ') === $dnsContent) {
					//Success
					return true;
				}
			}
		}
		//Try Dig against Authoritative Nameservers (Bypasses Cache)
		if(self::is_dig_supported()) {
			//Attempt to find the authoritative NS for the domain
			$nsRecords = @dns_get_record($domain, DNS_NS);
			$targetNs = !empty($nsRecords) ? "@" . $nsRecords[0]['target'] : "@8.8.8.8";
			//Use +short to get clean output
			$command = sprintf("dig %s %s TXT +short 2>&1", escapeshellarg($targetNs), escapeshellarg($host));
			exec($command, $output, $return_status);
			//Check output is what is expected
			if($return_status === 0 && !empty($output)) {
				foreach($output as $line) {
					if(trim($line, '" ') === $dnsContent) {
						//Success
						return true;
					}
				}
			}
		}
		//Failure
		return false;
	}

	/**
	 * Get common name for csr generation
	 * @param array $domainList
	 * @return mixed
	 */
	public static function is_dig_supported()
	{
		exec('dig -v 2>&1', $output, $return_var);
		return $return_var === 0;
	}

	/**
	 * Get common name for csr generation
	 * @param array $domainList
	 * @return mixed
	 */
	public static function getCommonNameForCSR(array $domainList)
	{
		$domainLevel = [];
		foreach($domainList as $domain) {
			$cleanDomain = ltrim($domain, '*.');
			$domainLevel[count(explode('.', $cleanDomain))][] = $cleanDomain;
		}
		ksort($domainLevel);
		$shortestList = reset($domainLevel);
		sort($shortestList);
		return $shortestList[0];
	}

	/**
	 * Get csr content without comment
	 * @param string $csr
	 * @return string
	 */
	public static function getCSRWithoutComment(string $csr)
	{
		return trim(preg_replace('/-----(?:BEGIN|END)\sCERTIFICATE\sREQUEST-----/i', '', $csr));
	}

	/**
	 * Get certificate content without comment
	 * @param string $certificate
	 * @return string
	 */
	public static function getCertificateWithoutComment(string $certificate)
	{
		return trim(preg_replace('/-----(?:BEGIN|END)\sCERTIFICATE-----/i', '', $certificate));
	}

	/**
	 * Extract certificate from server response
	 * @param string $certificateFromServer
	 * @return array|null
	 */
	public static function extractCertificate(string $certificateFromServer)
	{
		$pattern = '/-----BEGIN\sCERTIFICATE-----(.*?)-----END\sCERTIFICATE-----/is';
		if(preg_match_all($pattern, $certificateFromServer, $matches)) {
			return [
				'certificate' => trim($matches[0][0]),
				'certificateFullChained' => implode("\n", array_map('trim', $matches[0])),
			];
		}
		return null;
	}
}
