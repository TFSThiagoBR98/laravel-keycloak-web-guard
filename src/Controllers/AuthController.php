<?php

namespace TFSThiagoBR98\LaravelKeycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redirect;
use TFSThiagoBR98\LaravelKeycloak\Contracts\LoginResponse;
use TFSThiagoBR98\LaravelKeycloak\Contracts\LogoutResponse;
use TFSThiagoBR98\LaravelKeycloak\Contracts\RegisterResponse;
use TFSThiagoBR98\LaravelKeycloak\Exceptions\KeycloakCallbackException;
use TFSThiagoBR98\LaravelKeycloak\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        return App::instance(LoginResponse::class);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        return App::instance(LogoutResponse::class);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        return App::instance(RegisterResponse::class);
    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! KeycloakWeb::validateState($state)) {
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = App::config('laravel-keycloak.redirect_url', '/admin');
                return Redirect::intended($url);
            }
        }

        return Redirect::to(route('keycloak.login'));
    }
}
