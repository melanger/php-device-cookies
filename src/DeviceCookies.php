<?php

namespace DeviceCookies;

use DeviceCookies\Models\UserDeviceCookieFailedAttempts;
use DeviceCookies\Models\UserDeviceCookieLockout;

/**
 * Device cookies class for help prevent brute-force attack.
 * @see https://www.owasp.org/index.php/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
 */
class DeviceCookies
{
    /**
     * @var \PDO
     */
    protected $Dbh;

    /**
     * @var string The name of device cookie.
     */
    protected $deviceCookieName = 'deviceCookie';

    /**
     * @var int The number of days that this cookie will be expired.
     */
    protected $deviceCookieExpire = 730;

    /**
     * @var int Current failed attempts with in time period.
     */
    protected $currentFailedAttempt = 0;

    /**
     * @var array|null Contain lockout result object from `$UserDeviceCookieLockout->isInLockoutList()` method.
     */
    protected $lockoutResult;

    /**
     * @var int Max number of authentication attempts allowed during "time period".
     */
    protected $maxAttempt = 10;

    /**
     * @var string Server’s secret cryptographic key.
     */
    protected $secretKey = 'SkfEED4aKrNWFUNqgqf6hrFsJQ6K6Jhh';

    /**
     * @var int Time period (in seconds).
     */
    protected $timePeriod = 60;

    /**
     * Class constructor.
     *
     * @param array $options The options in associative array format.
     */
    public function __construct(array $options)
    {
        foreach ($options as $option => $value) {
            if (property_exists($this, $option)) {
                $this->{$option} = $value;
            }
        }// endforeach;
        unset($option, $value);
    }

    /**
     * Check for brute force.
     * @return DeviceCookiesResult What to do.
     */
    public function check(string $login, ?string $userId, bool $isPasswordCorrect)
    {
        $entrypoint = $this->checkEntryPoint($login, $userId);
        if ($entrypoint !== DeviceCookiesResult::AUTHENTICATE) {
            return $entrypoint;
        }

        return $this->checkAuthenticate($login, $isPasswordCorrect);
    }

    /**
     * Garbage collection to remove old data that is no longer used from DB.
     */
    public function cleanup($dbh)
    {
        $sql = 'DELETE FROM `user_devicecookie_failedattempts` WHERE `datetime` < NOW() - INTERVAL :time_period SECOND';
        $Sth = $dbh->prepare($sql);
        $Sth->bindValue(':time_period', $this->timePeriod + 10);
        $Sth->execute();
        $affected1 = $Sth->rowCount();

        $sql = 'DELETE FROM `user_devicecookie_lockout` WHERE `lockout_until` < NOW()';
        $Sth = $dbh->prepare($sql);
        $Sth->execute();
        $affected2 = $Sth->rowCount();

        return $affected1 + $affected2;
    }

    private function checkAuthenticate(string $login, ?string $userId, bool $isPasswordCorrect)
    {
        // 1. check user credentials
        if ($isPasswordCorrect) {
            // 2. if credentials are valid.
            // a. issue new device cookie to user’s client
            $this->issueNewDeviceCookie($login);
            // b. proceed with authenticated user
            $output = DeviceCookiesResult::SUCCESS;
        } else {
            // 3. else
            // a. register failed authentication attempt
            if ($userId !== null) {
                $this->registerFailedAuth($login, $userId);
            }
            // b. finish with failed user’s authentication
            if (
                is_numeric($this->currentFailedAttempt) &&
                $this->currentFailedAttempt > 0 &&
                is_numeric($this->maxAttempt) &&
                is_numeric($this->timePeriod)
            ) {
                $output = DeviceCookiesResult::LOCKOUT;
            } else {
                $output = DeviceCookiesResult::WRONG_PASSWORD;
            }
        }
        return $output;
    }

    /**
     * Entry point for authentication request
     *
     * @param string $login The login ID such as email.
     * @return DeviceCookiesResult What to do next.
     */
    private function checkEntryPoint(string $login, ?string $userId): string
    {
        $UserDeviceCookieLockout = new UserDeviceCookieLockout($this->Dbh);
        $output = '';
        if ($this->hasDeviceCookie() === true) {
            // 1. if the incoming request contains a device cookie.
            // --- a. validate device cookie
            $validateDeviceCookieResult = $this->validateDeviceCookie($login);
            if ($validateDeviceCookieResult !== true) {
                // b. if device cookie is not valid.
                // proceed to step 2.
                $this->removeDeviceCookie();
                $step2 = true;
            } elseif ($UserDeviceCookieLockout->isInLockoutList($this->getDeviceCookie()) === true) {
                // c. if the device cookie is in the lockout list (valid but in lockout list).
                // reject authentication attempt∎
                $output = DeviceCookiesResult::REJECT_VALID;
                $this->lockoutResult = $UserDeviceCookieLockout->getLockoutResult();
            } else {
                // d. else
                // authenticate user∎
                $output = DeviceCookiesResult::AUTHENTICATE;
            }
        } else {
            $step2 = true;
        }// endif;
        if (isset($step2) && $step2 === true) {
            if ($UserDeviceCookieLockout->isInLockoutList(null, $userId) === true) {
                // 2. if authentication from untrusted clients is locked out for the specific user.
                // reject authentication attempt∎
                $output = DeviceCookiesResult::REJECT;
                $this->lockoutResult = $UserDeviceCookieLockout->getLockoutResult();
            } else {
                // 3. else
                // authenticate user∎
                $output = DeviceCookiesResult::AUTHENTICATE;
            }// endif;
        } else {
            if (empty($output)) {
                // i don't think someone will be in this condition.
                $output = DeviceCookiesResult::REJECT;
                $this->lockoutResult = $UserDeviceCookieLockout->getLockoutResult();
            }
        }// endif;
        return $output;
    }

    /**
     * Get device cookie content
     *
     * @return string Return cookie value or content.
     */
    private function getDeviceCookie(): string
    {
        if ($this->hasDeviceCookie() === true) {
            return $_COOKIE[$this->deviceCookieName];
        }
        return '';
    }

    /**
     * Get device cookie as array.
     *
     * @param string|null $cookieValue The cookie value. Leave null to get it from cookie variable.
     *@return array Return array where 0 is login, 1 is nonce, 2 is signature.
     */
    private function getDeviceCookieArray(string $cookieValue = null): array
    {
        if ($cookieValue === null) {
            $cookieValue = $this->getDeviceCookie();
        }
        $exploded = explode(',', $cookieValue);
        if (is_array($exploded) && count($exploded) >= 3) {
            $output = $exploded;
        } else {
            $output = [
                '',
                null,
                null,
            ];
        }
        unset($cookieValue, $exploded);
        return $output;
    }

    /**
     * Check if the incoming request contains a device cookie.
     *
     * This is just check that there is device cookie or not. It was not check for valid or invalid device cookie.
     *
     * @return bool Return `true` if there is device cookie. Return `false` if not.
     */
    private function hasDeviceCookie(): bool
    {
        if (isset($_COOKIE[$this->deviceCookieName])) {
            return true;
        }
        return false;
    }

    /**
     * Issue new device cookie to user’s client.
     *
     * Issue a browser cookie with a value.
     *
     * @param string $login The login name (or internal ID).
     */
    private function issueNewDeviceCookie(string $login)
    {
        $nonce = $this->generateNonce();
        $signature = $this->getHmacSignature($login, $nonce);
        setcookie(
            $this->deviceCookieName,
            $login . ',' . $nonce . ',' . $signature,
            time() + ($this->deviceCookieExpire * 24 * 60 * 60),
            '/'
        );
    }

    /**
     * Register failed authentication attempt.
     */
    private function registerFailedAuth(string $login, ?string $userId)
    {
        $data = [
            'login' => $login,
            'user_id' => $userId,
        ];
        // get additional data from previous cookie.
        if (isset($data['login']) && $this->validateDeviceCookie($data['login']) === true) {
            // if a valid device cookie presented.
            $validDeviceCookie = true; // mark that valid device cookie is presented.
            list($login, $nonce, $signature) = $this->getDeviceCookieArray();
            $data['devicecookie_nonce'] = $nonce;
            $data['devicecookie_signature'] = $signature;
            unset($login, $nonce, $signature);
        }
        // sanitize $data
        if (isset($data['devicecookie_nonce']) && empty($data['devicecookie_nonce'])) {
            $data['devicecookie_nonce'] = null;
            unset($validDeviceCookie);
        }
        if (isset($data['devicecookie_signature']) && empty($data['devicecookie_signature'])) {
            $data['devicecookie_signature'] = null;
            unset($validDeviceCookie);
        }
        // 1. register a failed authentication attempt
        $UserDeviceCookieFailedAttempts = new UserDeviceCookieFailedAttempts($this->Dbh);
        $UserDeviceCookieFailedAttempts->addFailedAttempt($data);
        // 2. depending on whether a valid device cookie is present in the request,
        // count the number of failed authentication attempts within period T
        if (!isset($data['devicecookie_nonce']) || !isset($data['devicecookie_signature'])) {
            // a. all untrusted clients
            $where = [];
            $where['devicecookie_signature'] = null;
            $failedAttempts = $UserDeviceCookieFailedAttempts->countFailedAttemptInPeriod($this->timePeriod, $where);
        } else {
            // b. a specific device cookie
            $where = [];
            $where['devicecookie_signature'] = $data['devicecookie_signature'];
            $failedAttempts = $UserDeviceCookieFailedAttempts->countFailedAttemptInPeriod($this->timePeriod, $where);
        }
        $this->currentFailedAttempt = $failedAttempts;
        unset($UserDeviceCookieFailedAttempts, $where);
        // 3. if "number of failed attempts within period T" > N
        if ($failedAttempts > $this->maxAttempt) {
            $dataUpdate = [];
            $dataUpdate['user_id'] = $data['user_id'];
            $Datetime = new \Datetime();
            $Datetime->add(new \DateInterval('PT' . $this->timePeriod . 'S'));
            $dataUpdate['lockout_until'] = $Datetime->format('Y-m-d H:i:s');
            unset($Datetime);
            if (
                isset($validDeviceCookie) &&
                $validDeviceCookie === true
            ) {
                // a. if a valid device cookie is presented
                // put the device cookie into the lockout list for device cookies until now+T
                $dataUpdate['devicecookie_nonce'] = $data['devicecookie_nonce'];
                $dataUpdate['devicecookie_signature'] = $data['devicecookie_signature'];
            } else {
                // b. else
                // lockout all authentication attempts for a specific user from all untrusted clients until now+T
                $dataUpdate['lockout_untrusted_clients'] = 1;
            }
            $UserDeviceCookieLockout = new UserDeviceCookieLockout($this->Dbh);
            $UserDeviceCookieLockout->addUpdateLockoutList($dataUpdate);
            unset($UserDeviceCookieLockout);
        }
    }

    /**
     * Remove a device cookie.
     */
    private function removeDeviceCookie()
    {
        setcookie($this->deviceCookieName, '', time() - ($this->deviceCookieExpire * 24 * 60 * 60), '/');
    }

    /**
     * Validate device cookie.
     *
     * @partam string $userLogin The login ID input from user.
     * @return bool Return `true` if device cookie is correct and the `login` contained in the cookie is matches.
     */
    private function validateDeviceCookie(string $userLogin): bool
    {
        if ($this->hasDeviceCookie() === true) {
            $cookieValue = $_COOKIE[$this->deviceCookieName];
            list($login, $nonce, $signature) = $this->getDeviceCookieArray($cookieValue);
            if ($userLogin . ',' . $nonce . ',' . $signature === $cookieValue) {
                // 1. Validate that the device cookie is formatted as described
                if (
                    hash_equals(
                        $this->getHmacSignature($userLogin, $nonce),
                        $signature
                    )
                ) {
                    // 2. Validate that SIGNATURE == HMAC(secret-key, “LOGIN,NONCE”)
                    if ($login === $userLogin) {
                        // 3. Validate that LOGIN represents the user who is actually trying to authenticate
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Generate nonce
     *
     * @param int $length The string length.
     * @return string Return generated nonce.
     */
    private function generateNonce(int $length = 32): string
    {
        return base64_encode(random_bytes($length));
    }

    /**
     * Get HMAC signature content.
     *
     * @param string $login The login name.
     * @param string $nonce NONCE.
     * @return string Return generated string from HMAC.
     */
    private function getHmacSignature(string $login, string $nonce): string
    {
        return hash_hmac('sha512', $login . ',' . $nonce, $this->secretKey);
    }
}
