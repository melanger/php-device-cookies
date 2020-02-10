<?php

namespace DeviceCookies;

/**
 * Device cookies check result.
 */
abstract class DeviceCookieResult
{
    /**
     * Untrusted clients or invalid device cookie and is in lockout
     */
    public const REJECT = 'reject';

    /**
     * There is valid device cookie but entered wrong credentials too many attempts until gets lockout
     */
    public const REJECT_VALID = 'rejectvalid';

    /**
     * Able to continue authentication
     */
    public const AUTHENTICATE = 'authenticate';

    /**
     * Logged in successfully
     */
    public const SUCCESS = 'success';

    /**
     * Incorrect login or password (threshold has not been reached)
     */
    public const WRONG_PASSWORD = 'wrongpassword';

    /**
     * Incorrect login or password too many times resulted in lockout
     */
    public const LOCKOUT = 'lockout';
}
