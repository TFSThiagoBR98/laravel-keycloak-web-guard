<?php

namespace TFSThiagoBR98\LaravelKeycloak\Responses;

use TFSThiagoBR98\LaravelKeycloak\Contracts\LoginResponse as Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Redirect;
use TFSThiagoBR98\LaravelKeycloak\Facades\KeycloakWeb;

class KeyCloakLoginResponse implements Responsable
{
    public function toResponse($request): RedirectResponse
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return Redirect::to($url);
    }
}
