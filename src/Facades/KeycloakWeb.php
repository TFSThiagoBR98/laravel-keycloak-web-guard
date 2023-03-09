<?php

namespace TFSThiagoBR98\LaravelKeycloak\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string getLoginUrl()
 * @method static string getLogoutUrl()
 * @method static array getAccessToken(string $code)
 * @method static array getUserProfile(array $credentials)
 * @method static void forgetToken()
 * @method static bool validateState(string|null $state)
 * 
 * 
 */
class KeycloakWeb extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'keycloak-web';
    }
}
