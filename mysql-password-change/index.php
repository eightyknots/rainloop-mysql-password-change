<?php

require_once __DIR__ . DIRECTORY_SEPARATOR . 'MysqlPasswordChangeDriver.php';

class MysqlPasswordChangePlugin extends \RainLoop\Plugins\AbstractPlugin
{
    public function Init()
    {
        $this->addHook('main.fabrica', 'MainFabrica');
    }

    public function Supported()
    {
        // Check for PDO
        if (!extension_loaded('pdo') || !class_exists('PDO')) {
            return 'Please install the missing PDO extension with the mysql driver';
        }

        // Check for *either* OpenSSL ext or PHP 7 for mt_rand
        // This ensures better cryptographic values are used
        if (!MysqlPasswordChangeDriver::ALLOW_POOR_SECURITY) {
            if (!function_exists('random_bytes') && !function_exists('openssl_random_pseudo_bytes')) {
                return 'Could not find a cryptographically secure function to use for salts. ' .
                'Please install PHP 7 (or the random_bytes() function) or the OpenSSL extension.';
            }
        }

        // Check for mysql driver available in PDO
        $pdoDrivers = \PDO::getAvailableDrivers();
        if (!$pdoDrivers || !in_array('mysql', $pdoDrivers)) {
            return 'Could not detect a mysql driver in your PDO extension. Please install the mysql driver for PDO';
        }
    }

    /**
     * Gets current configuration
     * @param $sName
     * @param $oProvider
     */
    public function MainFabrica($sName, &$oProvider)
    {
        if ($sName !== 'change-password') {
            return;
        }

        $oProvider = new MysqlPasswordChangeDriver;
        $oProvider
            ->SetServerHost($this->Config()->Get('plugin', 'mysqlHost', ''))
            ->SetServerPort((int) $this->Config()->Get('plugin', 'mysqlPort', 3306))
            ->SetServerUser($this->Config()->Get('plugin', 'mysqlUser', ''))
            ->SetServerPass($this->Config()->Get('plugin', 'mysqlPass', ''))
            ->SetServerDatabase($this->Config()->Get('plugin', 'mysqlDatabase', ''))
            ->SetTableName($this->Config()->Get('plugin', 'dbUsersTable', ''))
            ->SetKeyCol($this->Config()->Get('plugin', 'tableKeyCol', ''))
            ->SetUsersCol($this->Config()->Get('plugin', 'tableUsersCol', ''))
            ->SetPasswordCol($this->Config()->Get('plugin', 'tablePasswordCol', ''))
            ->SetEncryptScheme($this->Config()->Get('plugin', 'encryptScheme', ''))
            ->SetShaRounds((int) $this->Config()->Get('plugin', 'encryptRounds', 5000))
            ->SetRandomGenerator((function_exists('random_bytes')) ? 'random' : 'openssl')
            ->SetLogger($this->Manager()->Actions()->Logger());
    }

    public function configMapping()
    {
        return [
            \RainLoop\Plugins\Property::NewInstance('mysqlHost')
                ->SetLabel('MySQL host')
                ->setDefaultValue('127.0.0.1'),
            \RainLoop\Plugins\Property::NewInstance('mysqlPort')
                ->SetLabel('MySQL port')
                ->SetDefaultValue(3306),
            \RainLoop\Plugins\Property::NewInstance('mysqlUser')
                ->SetLabel('MySQL user'),
            \RainLoop\Plugins\Property::NewInstance('mysqlPass')
                ->SetLabel('MySQL password')
                ->SetType(\RainLoop\Enumerations\PluginPropertyType::PASSWORD),
            \RainLoop\Plugins\Property::NewInstance('mysqlDatabase')
                ->SetLabel('Database name')
                ->SetDefaultValue('mailserver'),
            \RainLoop\Plugins\Property::NewInstance('dbUsersTable')
                ->SetLabel('Users table name')
                ->SetDefaultValue('users'),
            \RainLoop\Plugins\Property::NewInstance('tableKeyCol')
                ->SetLabel('ID (primary key) column name')
                ->SetDefaultValue('id'),
            \RainLoop\Plugins\Property::NewInstance('tableUsersCol')
                ->SetLabel('Users column name')
                ->SetDefaultValue('email'),
            \RainLoop\Plugins\Property::NewInstance('tablePasswordCol')
                ->SetLabel('Password column name')
                ->SetDefaultValue('password'),
            \RainLoop\Plugins\Property::NewInstance('encryptScheme')
                ->SetLabel('Encryption scheme')
                ->SetType(\RainLoop\Enumerations\PluginPropertyType::SELECTION)
                ->SetDefaultValue(MysqlPasswordChangeDriver::SUPPORTED_PASSWORD_SCHEMES)
                ->SetDescription('Select the encryption scheme you are using to encrypt passwords on your MySQL server'),
            \RainLoop\Plugins\Property::NewInstance('encryptRounds')
                ->SetLabel('SHA rounds')
                ->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
                ->SetDefaultValue(5000)
                ->SetDescription('Rounds only applicable if using sha256 or sha512 encryption schemes')
        ];
    }
}