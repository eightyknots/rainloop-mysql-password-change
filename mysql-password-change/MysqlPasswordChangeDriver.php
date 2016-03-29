<?php

class MysqlPasswordChangeDriver implements \RainLoop\Providers\ChangePassword\ChangePasswordInterface
{

    const ALLOW_POOR_SECURITY = false;

    const SUPPORTED_PASSWORD_SCHEMES = ['sha512_crypt', 'sha256_crypt', 'blowfish_crypt', 'php', 'mysql', 'sha1'];

    const RANDOM_BYTES_SIZE = 17;

    const PDO_OPTIONS = [
        \PDO::ATTR_PERSISTENT    => true,
        \PDO::ATTR_ERRMODE       => \PDO::ERRMODE_EXCEPTION
    ];

    private $_mysqlHost = '127.0.0.1';

    private $_mysqlPort = 3306;

    private $_mysqlUser = 'user';

    private $_mysqlPass = 'password';

    private $_dbName = 'mailserver';

    private $_tableName = 'users';

    private $_keyCol = 'id';

    private $_usersCol = 'email';

    private $_passwordCol = 'password';

    private $_scheme = 'sha1';

    private $_rounds = 5000;

    private $_generator = 'random';

    private $_logger = null;

    public function SetServerHost($host)
    {
        $this->_mysqlHost = $host;
        return $this;
    }

    public function SetServerPort($port)
    {
        if ((int) $port > 0) {
            $this->_mysqlPort = (int) $port;
        }

        return $this;
    }

    public function SetServerUser($user)
    {
        $this->_mysqlUser = $user;
        return $this;
    }

    public function SetServerPass($pass)
    {
        $this->_mysqlPass = $pass;
        return $this;
    }

    public function SetServerDatabase($dbName)
    {
        $this->_dbName = $dbName;
        return $this;
    }

    public function SetTableName($tableName)
    {
        $this->_tableName = $tableName;
        return $this;
    }

    public function SetKeyCol($keyCol)
    {
        $this->_keyCol = $keyCol;
        return $this;
    }

    public function SetUsersCol($usersCol)
    {
        $this->_usersCol = $usersCol;
        return $this;
    }

    public function SetPasswordCol($passwordCol)
    {
        $this->_passwordCol = $passwordCol;
        return $this;
    }

    public function SetEncryptScheme($scheme)
    {
        if (in_array($scheme, self::SUPPORTED_PASSWORD_SCHEMES, true)) {
            $this->_scheme = $scheme;
        }

        return $this;
    }

    public function SetShaRounds($rounds)
    {
        if ((int) $rounds > 0) {
            $this->_rounds = $rounds;
        }

        return $this;
    }

    public function SetRandomGenerator($generator)
    {
        $this->_generator = $generator;
        return $this;
    }

    public function SetLogger($logger)
    {
        if ($logger instanceof \MailSo\Log\Logger) {
            $this->_logger = $logger;
        }

        return $this;
    }

    /**
     * TODO: Implement domain-based setting to only allow certain domains from changing passwords
     * @param \RainLoop\Account $oAccount Rainloop account object
     * @return bool True if password can be changed, false otherwise
     */
    public function PasswordChangePossibility($oAccount)
    {
        // TODO: To implement domain-based setting
        return true;
    }

    /**
     * @param \Rainloop\Account $oAccount Rainloop account object
     * @param string $sPrevPassword Previous password to check
     * @param string $sNewPassword New password to set
     * @return bool True if password was changed, false otherwise
     */
    public function ChangePassword(\Rainloop\Account $oAccount, $sPrevPassword, $sNewPassword)
    {

        unset($sPrevPassword);

        if ($this->_logger) {
            $this->_logger->Write('Changing password for user '.$oAccount->Email());
        }

        // TODO: Implement password requirements

        try {
            // Connect to MySQL
            $dsn = 'mysql:host='.$this->_mysqlHost.';port='.$this->_mysqlPort.';dbname='.$this->_dbName;
            $pdoObject = new \PDO($dsn, $this->_mysqlUser, $this->_mysqlPass, self::PDO_OPTIONS);

            // Get account from database
            $stmtGetAccount = $pdoObject->prepare("SELECT {$this->_keyCol} AS id FROM {$this->_tableName} WHERE {$this->_usersCol} = ? LIMIT 1");
            if ($stmtGetAccount->execute([$oAccount->Email()])) {
                $mysqlAccount = $stmtGetAccount->fetch(\PDO::FETCH_ASSOC);

                if (is_array($mysqlAccount) && array_key_exists('id', $mysqlAccount)) {

                    // Make password change
                    $newPassword = $this->_encrypt($sNewPassword, $pdoObject);
                    $stmtPassChange = $pdoObject->prepare("UPDATE {$this->_tableName} SET {$this->_passwordCol} = ? WHERE {$this->_keyCol} = ?");

                    // Returns whether the change was successful
                    $stmtPassChange->execute([$newPassword, $mysqlAccount['id']]);

                    if ($stmtPassChange->rowCount() !== 1) {
                        $this->_logger->Write('Password could not be changed for only 1 user. Affected rows: ' . $stmtPassChange->rowCount());
                        return false;
                    } else {
                        return true;
                    }

                } else {
                    $this->_logger->WriteException('Could not get your account from the database');
                }
            } else {
                $this->_logger->WriteException('An error occurred looking up your account');
            }
        } catch (\Exception $e) {
            if ($this->_logger) {
                $this->_logger->WriteException($e);
            }
        }

        // Guarantee return
        return false;
    }

    /**
     * Encrypts a cleartext password using the one-way hash algorithm as specified
     * @param null $password Cleartext password
     * @param null $pdo PDO object password to function for mysql encryption
     * @return string Encrypted password hash value
     * @throws \Exception
     */
    private function _encrypt($password = null, $pdo = null)
    {
        if (strlen($password) < 1) {
            if ($this->_logger) {
                $this->_logger->WriteException('Cannot encrypt an empty password!');
            } else {
                throw new \Exception('Cannot encrypt an empty password!');
            }
        }

        switch($this->_scheme) {
            case 'sha1':
                return sha1($password);
            case 'php':
                if (function_exists('password_hash')) {
                    return password_hash($password, PASSWORD_DEFAULT);
                } else {
                    $this->_logger->WriteException('"php" encryption was selected, but password_hash() is not found (PHP >= 5.5)');
                    return null;
                }
            case 'mysql':
                return $this->_mysqlEncrypt($password, $pdo);
            case 'blowfish_crypt':
                // TODO: Allow validated cost parameter if blowfish is selected
                return crypt($password, '$2y$12$'.$this->_generateSalt(true));
            case 'sha256_crypt':
                return crypt($password, '$5$rounds='.$this->_rounds.'$'.$this->_generateSalt());
            case 'sha512_crypt':
                return crypt($password, '$6$rounds='.$this->_rounds.'$'.$this->_generateSalt());
            default:
                $this->_logger->WriteException('Cannot find a suitable encryption algorithm to use!');
                return null;
        }
    }

    /**
     * Generates a (hopefully) cryptographically secure salt based on "good" random byte generators.
     * This is, of course, unless ALLOW_POOR_SECURITY is enabled, and does not require PHP 7 or OpenSSL.
     * For Blowfish ($2y$) algorithms, the salt length is 22 characters. For SHA256/512 ($5$, $6$),
     * the salt length is 16 characters.
     * @param int $length Salt length in bytes
     * @return string (Secure) Returns a hex-based salt (Insecure) Returns a 16-character random salt
     */
    private function _generateSalt($blowfish = false)
    {
        $length = $blowfish ? 22 : 16;

        if (function_exists('random_bytes')) {
            return str_replace('+', '.', substr(base64_encode(random_bytes(self::RANDOM_BYTES_SIZE)), 0, $length));
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            return str_replace('+', '.', substr(base64_encode(openssl_random_pseudo_bytes(self::RANDOM_BYTES_SIZE)), 0, $length));
        } else if (self::ALLOW_POOR_SECURITY) {
            return substr(str_shuffle("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"), 0, $length);
        } else {
            $this->_logger->WriteException('Could not generate a salt because the required crypto-safe functions were not available.');
        }
    }

    /**
     * Uses an existing PDO connection to get the ENCRYPT() hash value from MySQL directly
     * @param string $password Plaintext password to encrypt
     * @param null $pdo PDO Object password to method
     * @return mixed
     */
    private function _mysqlEncrypt($password = '', $pdo = null)
    {
        if ($pdo instanceof \PDO) {
            $stmtEncrypt = $pdo->prepare('SELECT ENCRYPT(?) AS hash');
            if ($stmtEncrypt->execute([$password])) {
                $result = $stmtEncrypt->fetch(\PDO::FETCH_ASSOC);
                if (is_array($result) && array_key_exists('hash', $result)) {
                    return $result['hash'];
                } else {
                    $this->_logger->WriteException('Could not encrypt password using MySQL ENCRYPT()');
                }
            }
        }
    }
}
