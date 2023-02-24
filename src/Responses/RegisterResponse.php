<?php

namespace TFSThiagoBR98\LaravelKeycloak\Responses;

use TFSThiagoBR98\LaravelKeycloak\Contracts\RegisterResponse as Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Redirect;
use TFSThiagoBR98\LaravelKeycloak\Facades\KeycloakWeb;

class KeyCloakRegisterResponse implements Responsable
{
    public function toResponse($request): RedirectResponse
    {
        $url = KeycloakWeb::getRegisterUrl();
        return Redirect::to($url);
    }
}
