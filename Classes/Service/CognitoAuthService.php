<?php
/***************************************************************
 *  Copyright notice
 *
 *  This script is part of the Typo3 project. The Typo3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *  A copy is found in the textfile GPL.txt and important notices to the license
 *  from the author is found in LICENSE.txt distributed with these scripts.
 *
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/
namespace Peytz\Cognito\Service;

use Peytz\Cognito\Exception;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Sv\AuthenticationService;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use Peytz\Cognito\Domain\Model\ExtensionConfiguration;
use Namshi\JOSE\SimpleJWS;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

include 'phar://' . ExtensionManagementUtility::extPath('cognito') . 'Libraries/namshi-jose.phar/vendor/autoload.php';
include 'phar://' . ExtensionManagementUtility::extPath('cognito') . 'Libraries/phpseclib-phpseclib.phar/vendor/autoload.php';

/**
 * Cognito Authentication Service
 *
 * @package Peytz\Cognito
 * @subpackage Service
 * @author Momchil Vangelov <mva@peytz.dk>
 * @copyright  2017 Peytz & Co, peytz.dk
 */
class CognitoAuthService extends AuthenticationService
{
    /**
     * Extension configuration
     *
     * @var ExtensionConfiguration
     */
    protected $extensionConfiguration;

    /**
     * OpenID configuration
     *
     * @var \stdClass
     */
    protected $openIdConfiguration;

    /**
     * Dbal db adapter
     *
     * @var \TYPO3\CMS\Dbal\Database\DatabaseConnection
     */
    protected $db;

    /**
     * Find a user (eg. look up the user record in database when a login is sent)
     *
     * @return mixed User array or FALSE
     * @throws Exception
     */
    public function getUser()
    {
        // get token
        if (!$this->getExtensionConfiguration()->getJwtGetParamName()) {
            throw new Exception(
                "Invalid 'jwtGetParamName'. Check the extension (ext:cognito) configuration options from the extension manager!"
            );
        }
        if (empty($_GET[$this->getExtensionConfiguration()->getJwtGetParamName()])) {
            throw new Exception("Invalid user json web token (jwt). Empty \$_GET['{$this->getExtensionConfiguration()->getJwtGetParamName()}']");
        }
        $jwt = htmlspecialchars($_GET[$this->getExtensionConfiguration()->getJwtGetParamName()]);

        // load JWS
        $jws = SimpleJWS::load($jwt);

        // get key ID (kid) from token header
        $jwtHeader = $jws->getHeader();
        if (empty($jwtHeader['kid'])) {
            throw new Exception("Key ID (kid) not found in json web token!");
        }
        $jwtHeaderKid = $jwtHeader['kid'];

        // get public key
        $jwks = $this->fetchJsonWebKeySet(true);
        if (!isset($jwks[$jwtHeaderKid])) {
            throw new Exception("Public key configuration with kid '{$jwtHeaderKid}' not found in JSON Web Key Set (jwks)!");
        }
        $publicKeyConfiguration = $jwks[$jwtHeaderKid];
        $publicKey = $this->getPublicKey($publicKeyConfiguration->e, $publicKeyConfiguration->n);

        // signature verification
        if (!$jws->verify($publicKey, $publicKeyConfiguration->alg)) {
            throw new Exception("Signature verification failed!");
        }

        // expiration verification
        if ($jws->isExpired()) {
            throw new Exception("Token has been expired!!");
        }

        // get user cognito ID
        $payload = $jws->getPayload();
        if (empty($payload['sub'])) {
            throw new Exception("Invalid cognito user ID (sub)!");
        }
        $userCognitoId = $payload['sub'];

        // check user
        $user = $this->findUserByCognitoId($userCognitoId);
        if (!$user) {
            // insert new user
            $userUid = $this->insertUser($userCognitoId);
            $user = $this->findUser($userUid);
        }

        return $user;
    }

    /**
     * Authenticate a user (Check various conditions for the user that might invalidate its authentication, eg. password match, domain, IP, etc.)
     *
     * @param array $user Data of user.
     * @return int >= 200: User authenticated successfully.
     *                     No more checking is needed by other auth services.
     *             >= 100: User not authenticated; this service is not responsible.
     *                     Other auth services will be asked.
     *             > 0:    User authenticated successfully.
     *                     Other auth services will still be asked.
     *             <= 0:   Authentication failed, no more checking needed
     *                     by other auth services.
     */
    public function authUser(array $user)
    {
        return 300;
    }

    /**
     * Fetch JSON Web Key Set (public keys)
     *
     * @param boolean $arrayByKid  If set it will return an array indexed by kid (key ID)
     * @return mixed
     * @throws Exception
     */
    public function fetchJsonWebKeySet($arrayByKid = false)
    {
        $openIdConfiguration = $this->getOpenIdConfiguration();

        if (empty($openIdConfiguration->jwks_uri)) {
            throw new Exception("Invalid uri of JSON Web Key Set [JWK] document (jwks_uri)!");
        }

        $jwksJson = file_get_contents($openIdConfiguration->jwks_uri);

        if (!$jwksJson) {
            throw new Exception(
                'Can not load JSON Web Key Set [JWK] document from uri: '
                . $openIdConfiguration->jwks_uri
            );
        }

        $jwks = json_decode($jwksJson);
        if (!$jwks) {
            throw new Exception('Can not decode JSON Web Key Set [JWK] document!');
        }

        if ($arrayByKid) {
            $jwksByKid = array();

            foreach ($jwks->keys as $keyEntry) {
                $jwksByKid[$keyEntry->kid] = $keyEntry;
            }

            return $jwksByKid;
        }

        return $jwks;
    }

    /**
     * Get public key
     *
     * @param string $exponent
     * @param string $modulus
     * @return bool|string
     * @throws Exception
     */
    public function getPublicKey($exponent, $modulus)
    {
        if (empty($exponent)) {
            throw new Exception("Invalid 'exponent'!");
        }
        if (empty($modulus)) {
            throw new Exception("Invalid 'modulus'!");
        }

        $rsa = new RSA();
        $modulus = new BigInteger(base64_decode($modulus), 256);
        $exponent = new BigInteger(base64_decode($exponent), 256);
        $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
        $rsa->setPublicKey();

        return $rsa->getPublicKey();
    }

    /**
     * Get extension configuration
     * The @inject notation does not work in the context of Typo3 Auth Services. That's why the object manager is used
     *
     * @return ExtensionConfiguration
     */
    public function getExtensionConfiguration()
    {
        if (is_null($this->extensionConfiguration)) {
            $objectManager =
                \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
            $this->extensionConfiguration =
                $objectManager->get('Peytz\\Cognito\\Domain\\Model\\ExtensionConfiguration');
        }

        return $this->extensionConfiguration;
    }

    /**
     * Get OpenID configuration
     *
     * @return mixed|\stdClass
     * @throws Exception
     */
    public function getOpenIdConfiguration()
    {
        if (is_null($this->openIdConfiguration)) {
            if (!$this->getExtensionConfiguration()->getOpenIdProviderConfigurationUri()) {
                throw new Exception(
                    "Invalid 'openIdProviderConfigurationUri'. Check the extension (ext:cognito) configuration options from the extension manager!"
                );
            }
            $openIdConfigurationJson = file_get_contents($this->getExtensionConfiguration()->getOpenIdProviderConfigurationUri());
            if (!$openIdConfigurationJson) {
                throw new Exception(
                    'Can not load OpenID configuration information from uri: '
                    . $this->extensionConfiguration->getOpenIdProviderConfigurationUri()
                );
            }
            $openIdConfiguration = json_decode($openIdConfigurationJson);
            if (!$openIdConfiguration) {
                throw new Exception('Can not decode OpenID json configuration information!');
            }

            $this->openIdConfiguration = $openIdConfiguration;
        }

        return $this->openIdConfiguration;
    }

    /**
     * Get dbal db adapter
     *
     * @return \TYPO3\CMS\Dbal\Database\DatabaseConnection
     */
    public function getDb()
    {
        if (is_null($this->db)) {
            $this->db = $GLOBALS['TYPO3_DB'];
        }

        return $this->db;
    }

    /**
     * Find user
     *
     * @param int $uid
     * @return array|FALSE|NULL
     * @throws Exception
     */
    protected function findUser($uid)
    {
        if (empty($uid)) {
            throw new Exception("Invalid param 'uid'!");
        }

        $uid = (int) $uid;

        return $this->getDb()->exec_SELECTgetSingleRow(
            '*',
            'fe_users',
            'disable=0 AND deleted=0 AND uid=' . $uid
        );
    }

    /**
     * Find user by user cognito ID
     *
     * @param string $userCognitoId
     * @return array|FALSE|NULL
     * @throws Exception
     */
    protected function findUserByCognitoId($userCognitoId)
    {
        if (empty($userCognitoId)) {
            throw new Exception("Invalid param 'userCognitoId'!");
        }

        return $this->getDb()->exec_SELECTgetSingleRow(
            '*',
            'fe_users',
            'disable=0 AND deleted=0 AND tx_cognito_cognito_id =' . $this->getDb()->fullQuoteStr($userCognitoId, 'fe_users')
        );
    }

    /**
     * Find user group
     *
     * @param int $uid
     * @return array|FALSE|NULL
     * @throws Exception
     */
    protected function findUserGroup($uid)
    {
        if (empty($uid)) {
            throw new Exception("Invalid param 'uid'!");
        }

        $uid = (int) $uid;

        return $this->getDb()->exec_SELECTgetSingleRow(
            '*',
            'fe_groups',
            'deleted=0 AND uid=' . $uid
        );
    }

    /**
     * Insert new user
     *
     * @param string $userCognitoId
     * @return int
     * @throws Exception
     */
    protected function insertUser($userCognitoId)
    {
        if (empty($userCognitoId)) {
            throw new Exception("Invalid param 'userCognitoId'!");
        }

        $pid = $this->getExtensionConfiguration()->getStorageUsersFolderUid();
        $userGroupUid = $this->getExtensionConfiguration()->getUserGroupUid();

        if (empty($pid)) {
            throw new Exception(
                "Invalid 'storageUsersFolderUid'. Check the extension (ext:cognito) configuration options from the extension manager!"
            );
        }
        if (empty($userGroupUid)) {
            throw new Exception(
                "Invalid 'userGroupUid'. Check the extension (ext:cognito) configuration options from the extension manager!"
            );
        }

        // check if the usergroup exist
        $userGroup = $this->findUserGroup($userGroupUid);
        if (!$userGroup) {
            throw new Exception("Usergroup with uid '{$userGroupUid}' does not exist!");
        }

        // insert user
        $fields = array(
            'pid' => (int) $pid,
            'deleted' => 0,
            'disable' => 0,
            'lastlogin' => time(),
            'crdate' => time(),
            'tstamp' => time(),
            'usergroup' => (int) $userGroupUid,
            'username' => 'cognito_user_' . GeneralUtility::getRandomHexString(10),
            'password' => GeneralUtility::getRandomHexString(32),
            'tx_cognito_cognito_id' => $userCognitoId,
        );
        $this->getDb()->exec_INSERTquery('fe_users', $fields);

        return $this->getDb()->sql_insert_id();
    }
}