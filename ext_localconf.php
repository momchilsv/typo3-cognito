<?php

if (!defined('TYPO3_MODE')) {
	die ('Access denied.');
}

$extensionConfigration = new \Peytz\Cognito\Domain\Model\ExtensionConfiguration();

// Register Cognito authentication service with TYPO3
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService(
    'cognito',
    'auth',
    'tx_cognito_auth_service',
    array(
        'title' => 'Cognito Authentication',
        'description' => 'Cognito authentication service for Frontend',
        'subtype' => 'getUserFE,authUserFE',
        'available' => true,
        'priority' => $extensionConfigration->getPriority(),
        'quality' => $extensionConfigration->getQuality(),
        'os' => '',
        'exec' => '',
        'className' => \Peytz\Cognito\Service\CognitoAuthService::class,
    )
);