<?php
/**
 * ChallengeService class file
 *
 * @author Zhang Jinlong <466028373@qq.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2018 Zhang Jinlong
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */

namespace orangecam\acme2letsencrypt\services;

/**
 * Class ChallengeService
 * @package orangecam\acme2letsencrypt\services
 */
class ChallengeService
{
	/**
	 * Challenge type: http-01, dns-01
	 * @var string
	 */
	private $_type;

	/**
	 * challenge Credential
	 * @var array
	 */
	private $_credential;

	/**
	 * Authorization inntance
	 * @var \orangecam\acme2letsencrypt\services\AuthorizationService
	 */
	private $_authorication;

	/**
	 * ChallengeService constructor.
	 * @param string $type
	 * @param \orangecam\acme2letsencrypt\services\AuthorizationService $authorization
	 */
	public function __construct($type, $authorization)
	{
		$this->_type = $type;
		$this->_authorication = $authorization;
	}

	/**
	 * Get challenge type
	 * @return string
	 */
	public function getType()
	{
		return $this->_type;
	}

	/**
	 * Get challenge credential
	 * @return array
	 */
	public function getCredential()
	{
		return $this->_credential;
	}

	/**
	 * Set challenge credential
	 * @param array $credential
	 */
	public function setCredential($credential)
	{
		$this->_credential = $credential;
	}

	/**
	 * Verify
	 * @param int $verifyLocallyTimeout
	 * @param int $verifyCATimeout
	 * @return bool
	 * @throws \Exception
	 */
	public function verify($verifyLocallyTimeout = 0, $verifyCATimeout = 0)
	{
		$orderService = Client::$runtime->order;

		if ($orderService->isAllAuthorizationValid() === TRUE)
		{
			return TRUE;
		}

		return $this->_authorication->verify($this->_type, $verifyLocallyTimeout, $verifyCATimeout);
	}
}
