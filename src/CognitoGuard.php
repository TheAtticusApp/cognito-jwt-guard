<?php

namespace BenBjurstrom\CognitoGuard;

use BenBjurstrom\CognitoGuard\Exceptions\MethodNotSupportedException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

class CognitoGuard implements Guard
{
    use GuardHelpers;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var ProviderRepository
     */
    protected $provider;

    /**
     * @param ProviderRepository $provider
     * @param Request  $request
     *
     * @return void
     */
    public function __construct(Request $request, ProviderRepository $provider)
    {
        $this->request  = $request;
        $this->provider = $provider;
    }

    /**
     * Get the currently authenticated user.
     *
     * @throws
     * @return Authenticatable|null
     */
    public function user(){
        if ($this->user instanceof Authenticatable) {
            return $this->user;
        }

        $ts = app()->make(TokenService::class);

        if(!$jwt = $ts->getTokenFromRequest($this->request)){
            return null;
        }

        $payload = $ts->getPayloadFromToken($jwt);
        $cognitoUuid = $ts->getCognitoUuidFromPayload($payload);
        if (config('cognito.sso_groups')) {
            $cognitoGroups = $ts->getCognitoGroupsFromPayload($payload, false);
        }

        return $this->user = $this->provider->getCognitoUser($cognitoUuid, $jwt, $cognitoGroups);
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function validate(array $credentials = []){
        throw new MethodNotSupportedException('CognitoGuard does not support the validate method.');
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function attempt(array $credentials = [])
    {
        throw new MethodNotSupportedException('CognitoGuard does not support the attempt method.');
    }
}
