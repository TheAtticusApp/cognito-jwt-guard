<?php

namespace BenBjurstrom\CognitoGuard;

use BenBjurstrom\CognitoGuard\Exceptions\MissingRequiredAttributesException;
use Exception;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;


/**
 * Class ProviderRepository
 * @package BenBjurstrom\CognitoGuard
 */
class ProviderRepository
{
    /**
     * @var EloquentUserProvider
     */
    protected $provider;

    /**
     * ProviderRepository constructor.
     * @param EloquentUserProvider $provider
     */
    public function __construct(EloquentUserProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * @param string $cognitoUuid
     * @param string $jwt
     * @param string $cognitoGroups
     * @return Authenticatable | null
     */
    public function getCognitoUser(string $cognitoUuid, $jwt, $cognitoGroups) {
        $model = $this->provider->createModel();
        // this will get even soft-deleted accounts
        $user = $model->withTrashed()->where('cognito_uuid', $cognitoUuid)->first();
        // if soft-deleted return null
        if ($user && $user->deleted_at) {
            return null; // this will cause the middleware to return unauthorized
        }

        if ($user) {
            return $user;
        }

        return $this->createSsoUser($cognitoUuid, $jwt, $cognitoGroups);
    }


    /**
     * @param string $cognitoUuid
     * @param string $jwt
     * @param string $cognitoGroups
     * @return Model
     * @throws
     */
    public function createSsoUser($cognitoUuid, $jwt, $cognitoGroups): Model
    {
        if(!config('cognito.sso')){
            return null;
        };

        $attributes = $this->getAttributes($jwt);
        $attributeKeys = collect(config('cognito.sso_user_attributes'));
        // cognito.sso_user_attributes will contain key/value pairs as follows:
        //  '{cognito_field_name}' => '{sql_field_name}',
        //  'email' => 'email',
        //  'phone_number' => 'phone',
        //  'custom:country_id' => 'countries_id',
        //  'custom:language_id' => 'languages_id',

        $user = $this->provider->createModel();
        $user->cognito_uuid = $cognitoUuid;
        foreach($attributeKeys as $cognitoAttribute => $sqlField){
            $key = strpos($cognitoAttribute, 'custom:', 0) ? substr($cognitoAttribute, 7) : $cognitoAttribute;
            try {
                $user->$sqlField = $attributes[$key];
            } catch (Exception $e) {
                // if config('error_if_missing_attr') will be caught in getAttributes
            }
        }
        if ($cognitoGroups) {
            $user->cognito_groups = $cognitoGroups;
        }
        if($repositoryClass = config('cognito.sso_repository_class')){
            $repository = resolve($repositoryClass);

            throw_unless(method_exists($repository, 'createCognitoUser'),
                new \LogicException($repositoryClass . ' does not have a method named createCognitoUser')
            );

            return $repository->createCognitoUser($user);
        }

        $user->save();
        return $user;
    }

    /**
     * @param $jwt
     * @return mixed
     * @throws
     */
    public function getAttributes($jwt){
        $uas = app()->make(UserAttributeService::class);

        $attributes = $uas->getUserAttributesFromToken($jwt);
        $requiredKeys = collect(config('cognito.sso_user_attributes'));

        if (config('cognito.error_if_missing_attr')) {
            $this->validateAttributes($attributes, $requiredKeys);
        }

        return $attributes;
    }

    /**
     * Ensures that all required attributes specified in the config were
     * returned from cognito.
     *
     * @param Collection $attributes
     * @param array $requiredKeys
     * @throws
     */
    public function validateAttributes(Collection $attributes, Collection $requiredKeys)
    {
        $diff = $requiredKeys->diff($attributes->keys());
        throw_unless($diff->isEmpty(), new MissingRequiredAttributesException('Required attributes (' . $diff->implode(',') . ') were not returned by cognito'));
    }
}
