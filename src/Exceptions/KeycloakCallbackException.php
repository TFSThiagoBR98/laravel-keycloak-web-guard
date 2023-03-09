<?php

namespace TFSThiagoBR98\LaravelKeycloak\Exceptions;

class KeycloakCallbackException extends \RuntimeException
{
    /**
     * Keycloak Callback Error
     *
     * @param string $error
     */
    public function __construct(string $error = '')
    {
        $message = '[Keycloak Error] ' . $error;

        parent::__construct($message);
    }
}
