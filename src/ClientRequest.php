<?php
/**
 * ClientRequest class file
 *
 * @author Cameron Brown <orangecam@msn.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2025 Cameron Brown
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */
namespace orangecam\acme2letsencrypt;

/**
 * Class ClientRequest
 * @package orangecam\acme2letsencrypt
 */
class ClientRequest
{
	/**
	 * RunRequest instance
	 * @var RunRequest
	 */
	public static $runRequest;

	/**
	 * Client constructor.
	 * @param array $emailList
	 * @param string $storagePath
	 * @param bool $staging
	 */
	public function __construct(array $emailList, string $storagePath, bool $staging = FALSE)
	{
		//Make a new instance and save it for use
		self::$runRequest = new RunRequest($emailList, $storagePath, $staging);
		//Run init, to setup some stuff
		self::$runRequest->init();
	}

	/**
	 * Get account service instance
	 * @return services\AccountService
	 */
	public function getAccount()
	{
		//Return the AccountService for the user to use it
		return self::$runRequest->account;
	}

	/**
	 * Get order service instance
	 * @param array $domainInfo
	 * @param int $algorithm
	 * @param bool $generateNewOder
	 * @return services\OrderService
	 * @throws \Exception
	 */
	public function getOrder(array $domainInfo, int $algorithm, bool $generateNewOder = TRUE)
	{
		//Return the order being requested
		return self::$runRequest->getOrder($domainInfo, $algorithm, $generateNewOder);
	}
}
