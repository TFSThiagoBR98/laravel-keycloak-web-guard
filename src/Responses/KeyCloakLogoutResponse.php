<?php

namespace TFSThiagoBR98\LaravelKeycloak\Responses;

use TFSThiagoBR98\LaravelKeycloak\Contracts\LogoutResponse as Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Redirect;
use TFSThiagoBR98\LaravelKeycloak\Facades\KeycloakWeb;

class KeyCloakLogoutResponse implements Responsable
{
    public function toResponse($request): RedirectResponse
    {
        $url = KeycloakWeb::getLogoutUrl();
        KeycloakWeb::forgetToken();
        return Redirect::to($url);
    }
}
