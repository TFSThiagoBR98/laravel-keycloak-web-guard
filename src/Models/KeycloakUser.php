<?php

namespace TFSThiagoBR98\LaravelKeycloak\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Auth;
use Spatie\SchemalessAttributes\Casts\SchemalessAttributes;

/**
 * Keycloak Base User
 * 
 * @property string $email
 * @property string $name
 * @property \Spatie\SchemalessAttributes\SchemalessAttributes $extra_attributes
 */
class KeycloakUser extends Authenticatable
{
    use HasUlids;

    /**
     * Attributes we retrieve from Profile
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email'
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'extra_attributes' => SchemalessAttributes::class,
    ];

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return 'email';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->email;
    }

    /**
     * Check user has roles
     *
     * @see KeycloakWebGuard::hasRole()
     *
     * @param  string|array  $roles
     * @param  string  $resource
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return Auth::hasRole($roles, $resource);
    }

    /**
     * Get the password for the user.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getAuthPassword()
    {
        return null;
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberToken()
    {
        return null;
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param string $value
     * @codeCoverageIgnore
     */
    public function setRememberToken($value)
    {
        return null;
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberTokenName()
    {
        return null;
    }
}
