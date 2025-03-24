<?php
/**
 * OpenSSLHelper class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\helpers;

use orangecam\acme2letsencrypt\constants\ConstantVariables;
use orangecam\acme2letsencrypt\ClientRequest;

/**
 * Class OpenSSLHelper
 * @package orangecam\acme2letsencrypt\helpers
 */
class OpenSSLHelper
{
	/**
	 * Generate private/public key pair
	 * @param $type
	 * @return array
	 * @throws \Exception
	 */
	public static function generateKeyPair(int $type)
	{
		$configMap = [
			ConstantVariables::KEY_PAIR_TYPE_RSA => [
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'private_key_bits' => 4096,
			],

			ConstantVariables::KEY_PAIR_TYPE_EC => [
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name' => 'secp384r1',
			],
		];

		$typeNameMap = [
			ConstantVariables::KEY_PAIR_TYPE_RSA => 'RSA',
			ConstantVariables::KEY_PAIR_TYPE_EC => 'EC',
		];

		$resource = openssl_pkey_new($configMap[$type]);

		if($resource === FALSE) {
			throw new \Exception("Generate {$typeNameMap[$type]} key pair failed.");
		}

		if(openssl_pkey_export($resource, $privateKey) === FALSE) {
			throw new \Exception("Export {$typeNameMap[$type]} private key failed.");
		}

		$detail = openssl_pkey_get_details($resource);

		if($detail === FALSE) {
			throw new \Exception("Get {$typeNameMap[$type]} key details failed.");
		}

		return [
			'privateKey' => $privateKey,
			'publicKey' => $detail['key'],
		];
	}

	/**
	 * Generate CSR content
	 * @param array $domainList
	 * @param array $dn
	 * @param string $privateKey
	 * @return mixed
	 */
	public static function generateCSR($domainList, $dn, $privateKey)
	{
		$san = array_map(
			function($domain) {
				return "DNS:{$domain}";
			},
			$domainList
		);

		$opensslConfigFileResource = tmpfile();
		$opensslConfigFileMeta = stream_get_meta_data($opensslConfigFileResource);
		$opensslConfigFilePath = $opensslConfigFileMeta['uri'];

		$content = "
			HOME = .
			RANDFILE = \$ENV::HOME/.rnd
			[ req ]
			default_bits = 4096
			default_keyfile = privkey.pem
			distinguished_name = req_distinguished_name
			req_extensions = v3_req
			[ req_distinguished_name ]
			countryName = Country Name (2 letter code)
			[ v3_req ]
			basicConstraints = CA:FALSE
			subjectAltName = ".implode(',', $san)."
			keyUsage = nonRepudiation, digitalSignature, keyEncipherment
		";

		fwrite($opensslConfigFileResource, $content);

		$privateKey = openssl_pkey_get_private($privateKey);

		$csr = openssl_csr_new(
			$dn,
			$privateKey,
			[
				'config' => $opensslConfigFilePath,
				'digest_alg' => 'sha256',
			]
		);

		openssl_csr_export($csr, $csr);

		return $csr;
	}

	/**
	 * Generate thumbprint
	 * @param string|null $privateKey
	 * @return mixed
	 */
	public static function generateThumbprint($privateKey = NULL)
	{
		$privateKey = openssl_pkey_get_private($privateKey ?: ClientRequest::$runRequest->account->getPrivateKey());
		$detail = openssl_pkey_get_details($privateKey);

		$accountKey = [
			'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
			'kty' => 'RSA',
			'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
		];

		return CommonHelper::base64UrlSafeEncode(hash('sha256', json_encode($accountKey), TRUE));
	}

	/**
	 * Generate JWS(Json Web Signature) with field `jwk`
	 * @param string $url
	 * @param array|string $payload
	 * @param string|null $privateKey
	 * @return string
	 * @throws \Exception
	 */
	public static function generateJWSOfJWK($url, $payload, $privateKey = NULL)
	{
		$privateKey = openssl_pkey_get_private($privateKey ?: ClientRequest::$runRequest->account->getPrivateKey());
		$detail = openssl_pkey_get_details($privateKey);

		$protected = [
			'alg' => 'RS256',
			'jwk' => [
				'kty' => 'RSA',
				'n' => CommonHelper::base64UrlSafeEncode($detail['rsa']['n']),
				'e' => CommonHelper::base64UrlSafeEncode($detail['rsa']['e']),
			],
			'nonce' => ClientRequest::$runRequest->nonce->getNewNonce(),
			'url' => $url,
		];

		$protectedBase64 = CommonHelper::base64UrlSafeEncode(json_encode($protected));
		$payloadBase64 = CommonHelper::base64UrlSafeEncode(is_array($payload) ? json_encode($payload) : $payload);

		openssl_sign($protectedBase64.'.'.$payloadBase64, $signature, $privateKey, 'SHA256');
		$signatureBase64 = CommonHelper::base64UrlSafeEncode($signature);

		return json_encode([
			'protected' => $protectedBase64,
			'payload' => $payloadBase64,
			'signature' => $signatureBase64,
		]);
	}

	/**
	 * Generate JWS(Json Web Signature) with field `kid`
	 * @param string $url
	 * @param string $kid
	 * @param array|string $payload
	 * @return string
	 * @throws \Exception
	 */
	public static function generateJWSOfKid($url, $kid, $payload)
	{
		$privateKey = openssl_pkey_get_private(ClientRequest::$runRequest->account->getPrivateKey());

		$protected = [
			'alg' => 'RS256',
			'kid' => $kid,
			'nonce' => ClientRequest::$runRequest->nonce->getNewNonce(),
			'url' => $url,
		];

		$protectedBase64 = CommonHelper::base64UrlSafeEncode(json_encode($protected));
		$payloadBase64 = CommonHelper::base64UrlSafeEncode(is_array($payload) ? json_encode($payload) : $payload);

		openssl_sign($protectedBase64.'.'.$payloadBase64, $signature, $privateKey, 'SHA256');
		$signatureBase64 = CommonHelper::base64UrlSafeEncode($signature);

		return json_encode([
			'protected' => $protectedBase64,
			'payload' => $payloadBase64,
			'signature' => $signatureBase64,
		]);
	}
}
