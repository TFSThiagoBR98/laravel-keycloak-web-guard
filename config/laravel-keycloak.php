<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', ''),

    /**
     * Keycloak Realm
     *
     * Default is master
     */
    'realm' => env('KEYCLOAK_REALM', 'master'),

    /**
     * The Keycloak Server realm public key (string).
     *
     * @see Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key
     */
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    /**
     * Keycloak Client ID
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),

    /**
     * Keycloak Client Secret
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),

    /**
     * We can cache the OpenId Configuration
     * The result from /realms/{realm-name}/.well-known/openid-configuration
     *
     * @link https://www.keycloak.org/docs/3.2/securing_apps/topics/oidc/oidc-generic.html
     */
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),

    /**
     * Page to redirect after callback if there's no "intent"
     *
     * @see TFSThiagoBR98\LaravelKeycloak\Controllers\AuthController::callback()
     */
    'redirect_url' => '/admin',

    /**
     * The routes for authenticate
     *
     * Accept a string as the first parameter of route() or false to disable the route.
     *
     * The routes will receive the name "keycloak.{route}" and login/callback are required.
     * So, if you make it false, you shoul register a named 'keycloak.login' route and extend
     * the TFSThiagoBR98\LaravelKeycloak\Controllers\AuthController controller.
     */
    'routes' => [
        'login' => 'login',
        'logout' => 'logout',
        'register' => 'register',
        'callback' => 'callback',
    ],

    /**
     * GuzzleHttp Client options
     *
     * @link http://docs.guzzlephp.org/en/stable/request-options.html
     */
    'guzzle_options' => [],

    /**
     * 
     */
    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),

    /**
     * 
     */
    'user_provider_custom_retrieve_method' => null,

    /**
     * 
     */
    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),

    /**
     * 
     */
    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'preferred_username'),

    /**
     * 
     */
    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),

    /**
     * 
     */
    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null),

    /**
     * 
     */
    'ignore_resources_validation' => env('KEYCLOAK_IGNORE_RESOURCES_VALIDATION', false),

    /**
     * 
     */
    'leeway' => env('KEYCLOAK_LEEWAY', 0),

    /**
     * 
     */
    'input_key' => env('KEYCLOAK_TOKEN_INPUT_KEY', null)
];
