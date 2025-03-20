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
	public function base64UrlSafeEncode($string)
	{
		return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
	}

	/**
	 * Get replay nonce from http response header
	 * @param string $header
	 * @return bool|string
	 */
	public function getNonceFromResponseHeader($header)
	{
		return $this->getFieldFromHeader('Replay-Nonce', $header);
	}

	/**
	 * Get location field from http response header
	 * @param string $header
	 * @return bool|string
	 */
	public function getLocationFieldFromHeader($header)
	{
		return $this->getFieldFromHeader('Location', $header);
	}

	/**
	 * Get field from http response header
	 * @param string $field
	 * @param string $header
	 * @return bool|string
	 */
	public function getFieldFromHeader($field, $header)
	{
		if(!preg_match("/{$field}:\s*(\S+)/i", $header, $matches)){
			return FALSE;
		}

		return trim($matches[1]);
	}

	/**
	 * Check http challenge locally, this challenge must be accomplished via http not https
	 * @param string $domain
	 * @param string $fileName
	 * @param string $fileContent
	 * @return bool
	 */
	public function checkHttpChallenge($domain, $fileName, $fileContent)
	{
		$url = "http://{$domain}/.well-known/acme-challenge/{$fileName}";

		try {
			list(, , $body) = RequestHelper::get($url);
		}
		catch(\Exception $e) {
			return FALSE;
		}

		if($body == $fileContent) {
			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Check dns challenge locally
	 * @param string $domain
	 * @param string $dnsContent
	 * @return bool
	 */
	public function checkDNSChallenge($domain, $dnsContent)
	{
		$host = '_acme-challenge.'.str_replace('*.', '', $domain);
		$recordList = @dns_get_record($host, DNS_TXT);

		if(is_array($recordList)) {
			foreach($recordList as $record) {
				if($record['type'] == 'TXT' && $record['txt'] == $dnsContent) {
					return TRUE;
				}
			}
		}

		return FALSE;
	}

	/**
	 * Get common name for csr generation
	 * @param array $domainList
	 * @return mixed
	 */
	public function getCommonNameForCSR($domainList)
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
	public function getCSRWithoutComment($csr)
	{
		$pattern = '/-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----/is';

		if(preg_match($pattern, $csr, $matches)) {
			return trim($matches[1]);
		}

		return $csr;
	}

	/**
	 * Get certificate content without comment
	 * @param string $certificate
	 * @return string
	 */
	public function getCertificateWithoutComment($certificate)
	{
		$pattern = '/-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----/is';

		if(preg_match($pattern, $certificate, $matches)) {
			return trim($matches[1]);
		}

		return $certificate;
	}

	/**
	 * Extract certificate from server response
	 * @param string $certificateFromServer
	 * @return array|null
	 */
	public function extractCertificate($certificateFromServer)
	{
		$certificate = '';
		$certificateFullChained = '';
		$pattern = '/-----BEGIN\sCERTIFICATE-----(.*?)-----END\sCERTIFICATE-----/is';

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

		return NULL;
	}
}
