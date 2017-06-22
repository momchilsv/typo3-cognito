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
namespace Peytz\Cognito\Domain\Model;

use TYPO3\CMS\Core\SingletonInterface;

/**
 * Object containing the extension configuration
 *
 * @package Peytz\Cognito
 * @subpackage Model
 * @author Momchil Vangelov <mva@peytz.dk>
 * @copyright  2017 Peytz & Co, peytz.dk
 */
class ExtensionConfiguration implements SingletonInterface
{
    /**
     * Raw configuration
     *
     * @var array
     */
    protected $configurationArray = array();

    /**
     * OpenID Provider Configuration URI
     *
     * @var string
     */
    protected $openIdProviderConfigurationUri;

    /**
     * Get param name for jwt : $_GET param, which holds the 'jwt' token
     *
     * @var string
     */
    protected $jwtGetParamName;

    /**
     * Storage users folder UID : Storage system folder, where all new cognito users will be saved locally
     *
     * @var int
     */
    protected $storageUsersFolderUid;

    /**
     * User group UID : User group for all newly created local cognito users
     *
     * @var int
     */
    protected $userGroupUid;

    /**
     * Service priority
     *
     * @var int
     */
    protected $priority;

    /**
     * Service quality
     *
     * @var int
     */
    protected $quality;

    /**
     * Constructor
     *
     * Reads the global configuration and calls the setter methods
     */
    public function __construct()
    {
        // Get global configuration
        $this->configurationArray = unserialize($GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['cognito']);
        if (is_array($this->configurationArray)) {
            // Call setter method foreach configuration entry
            foreach ($this->configurationArray as $key => $value) {
                $methodName = 'set' . ucfirst($key);
                if (method_exists($this, $methodName)) {
                    $this->$methodName($value);
                }
            }
        }
    }

    /**
     * Returns the extension configuration as array
     *
     * @return array
     */
    public function toArray()
    {
        return $this->configurationArray;
    }

    /**
     * @return string
     */
    public function getOpenIdProviderConfigurationUri()
    {
        return $this->openIdProviderConfigurationUri;
    }

    /**
     * @param string $openIdProviderConfigurationUri
     */
    public function setOpenIdProviderConfigurationUri($openIdProviderConfigurationUri)
    {
        $this->openIdProviderConfigurationUri = $openIdProviderConfigurationUri;
    }

    /**
     * @return string
     */
    public function getJwtGetParamName()
    {
        return $this->jwtGetParamName;
    }

    /**
     * @param string $jwtGetParamName
     */
    public function setJwtGetParamName($jwtGetParamName)
    {
        $this->jwtGetParamName = $jwtGetParamName;
    }

    /**
     * @return int
     */
    public function getStorageUsersFolderUid()
    {
        return $this->storageUsersFolderUid;
    }

    /**
     * @param int $storageUsersFolderUid
     */
    public function setStorageUsersFolderUid($storageUsersFolderUid)
    {
        $this->storageUsersFolderUid = $storageUsersFolderUid;
    }

    /**
     * @return int
     */
    public function getUserGroupUid()
    {
        return $this->userGroupUid;
    }

    /**
     * @param int $userGroupUid
     */
    public function setUserGroupUid($userGroupUid)
    {
        $this->userGroupUid = $userGroupUid;
    }

    /**
     * @return int
     */
    public function getPriority()
    {
        return $this->priority;
    }

    /**
     * @param int $priority
     */
    public function setPriority($priority)
    {
        $this->priority = $priority;
    }

    /**
     * @return int
     */
    public function getQuality()
    {
        return $this->quality;
    }

    /**
     * @param int $quality
     */
    public function setQuality($quality)
    {
        $this->quality = $quality;
    }
}