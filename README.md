# PHP device cookies
Implementation of Device Cookies in PHP

Heavily based on [Device cookie example](https://github.com/Rundiz/device-cookies-example), which is an implementation of [Device cookies](https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies) described by OWASP.

## Installation

```
composer require cesnet/php-device-cookies
```

## Usage

Use the provided `DeviceCookies` class.

### Example

```php
$login = filter_input(INPUT_POST, 'login', FILTER_SANITIZE_EMAIL);
$password = filter_input(INPUT_POST, 'password');

if (!empty($login) && !empty($password)) {
	$user = getUserByLogin($login);
	$user_id = $user !== null ? $login : null;
	$isPasswordCorrect = password_verify($password, $user->password);
	$dbh = new PDO('dsn', 'username', 'password');

	$deviceCookies = new DeviceCookies([
	    'Dbh' => $dbh,
	    'deviceCookieExpire' => 730, // The number of days that this cookie will be expired
	    'maxAttempt' => 10, // max number of authentication attempts allowed during "time period"
	    'secretKey' => 'SkfEED4aKrNWFUNqgqf6hrFsJQ6K6Jhh', // server’s secret cryptographic key
	    'timePeriod' => 60, // time period (in seconds)
	]);

	$result = $deviceCookies->check($login, $user_id, $isPasswordCorrect);

	switch ($result) {
		case DeviceCookiesResult::SUCCESS:
			echo 'Logged in';
			break;
		case DeviceCookiesResult::REJECT:
		case DeviceCookiesResult::REJECT_VALID:
			http_response_code(403);
			exit;
		case DeviceCookiesResult::WRONG_PASSWORD:
		case DeviceCookiesResult::LOCKOUT:
			http_response_code(401);
			exit;
	}
}

// This should be called from a cron job once a day.
$deviceCookies->cleanup($dbh);
```
