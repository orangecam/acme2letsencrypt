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
	public RunRequest $runRequest;

	/**
	 * Client constructor.
	 * @param array $emailList
	 * @param string $storagePath
	 * @param bool $staging
	 */
	public function __construct(array $emailList, string $storagePath, bool $staging = FALSE)
	{
		//Make a new instance and save it for use
		$this->runRequest = new RunRequest($emailList, $storagePath, $staging);
	}

	/**
	 * Get account service instance
	 * @return services\AccountService
	 */
	public function getAccount()
	{
		//Return the AccountService for the user to use it
		return $this->runRequest->account;
	}

	/**
	 * Get order service instance
	 * @param array $domainInfo
	 * @param int $algorithm
	 * @param bool $generateNewOrder
	 * @return services\OrderService
	 * @throws \Exception
	 */
	public function getOrder(array $domainInfo, int $algorithm, bool $generateNewOrder = TRUE)
	{
		//Return the order being requested
		return $this->runRequest->getOrder($domainInfo, $algorithm, $generateNewOrder);
	}
}
