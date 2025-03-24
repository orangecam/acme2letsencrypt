<?php
/**
 * RunRequest class file
 *
 * @author Cameron Brown <orangecam@msn.com>
 * @link https://github.com/stonemax/acme2
 * @copyright Copyright &copy; 2025 Cameron Brown
 * @license https://opensource.org/licenses/mit-license.php MIT License
 */
namespace orangecam\acme2letsencrypt;

use orangecam\acme2letsencrypt\acme2services\AccountService;
use orangecam\acme2letsencrypt\acme2services\EndpointService;
use orangecam\acme2letsencrypt\acme2services\NonceService;
use orangecam\acme2letsencrypt\acme2services\OrderService;

/**
 * Class RunRequest
 * @package orangecam\acme2letsencrypt
 */
class RunRequest
{
	/**
	 * Email list
	 * @var array
	 */
	public $emailList;

	/**
	 * Storage path for certificate keys, public/private key pair and so on
	 * @var string
	 */
	public $storagePath;

	/**
	 * If staging status
	 * @var bool
	 */
	public $staging;

	/**
	 * Account service instance
	 * @var \orangecam\acme2letsencrypt\acme2services\AccountService
	 */
	public $account;

	/**
	 * Order service instance
	 * @var \orangecam\acme2letsencrypt\acme2services\OrderService
	 */
	public $order;

	/**
	 * Endpoint service instance
	 * @var \orangecam\acme2letsencrypt\acme2services\EndpointService
	 */
	public $endpoint;

	/**
	 * Nonce service instance
	 * @var \orangecam\acme2letsencrypt\acme2services\NonceService
	 */
	public $nonce;

	/**
	 * Constructor
	 * @param array $emailList
	 * @param string $storagePath
	 * @param bool $staging
	 */
	public function __construct(array $emailList, string $storagePath, bool $staging = FALSE)
	{
		//Save the email list
		$this->emailList = array_filter(array_unique($emailList));
		//Sort it
		sort($this->emailList);
		//Save the storage path
		$this->storagePath = rtrim(trim($storagePath), '/\\');
		//Staging, true or false
		$this->staging = boolval($staging);
	}

	/**
	 * Init
	 */
	public function init()
	{
		//Setup the endpoint service to make queries to the acme2 api
		$this->endpoint = new EndpointService($this->staging);
		//Setup the account service
		$this->account = new AccountService($this->storagePath.'/account');
		//Setup the nonce service
		$this->nonce = new NonceService($this->endpoint);
		//Get the account details
		$this->account->init();
	}

	/**
	 * Get order service instance
	 * @param array $domainInfo
	 * @param string $algorithm
	 * @param bool $generateNewOder
	 * @return OrderService
	 * @throws \Exception
	 */
	public function getOrder(array $domainInfo, string $algorithm, bool $generateNewOder = true)
	{
		if(!$this->order) {
			$this->order = new OrderService($domainInfo, $algorithm, $generateNewOder);
		}

		return $this->order;
	}
}
