<?php

return [

    /*
    |--------------------------------------------------------------------------
    | AWS Cognito User Pool and App Client Settings
    |--------------------------------------------------------------------------
    | Provide the cognito user pool id and user pool region.
    |
    | See this guide for help setting up a user pool:
    | https://serverless-stack.com/chapters/create-a-cognito-user-pool.html
    |
    |
    */

    'user_pool_id'      => env('AWS_COGNITO_USER_POOL_ID'),
    'user_pool_region'  => env('AWS_COGNITO_REGION'),
    'user_pool_client_id'  => env('AWS_COGNITO_CLIENT_ID'),

    /*
    |--------------------------------------------------------------------------
    | Single Sign-On Settings
    |--------------------------------------------------------------------------
    | If sso is true the cognito guard will automatically create a new user
    | record anytime the username attribute contained in a validated JWT
    | does not already exist in the users table.
    |
    | The new user will be created with the user attributes listed here
    | using the values stored in the given cognito user pool. Each attribute
    | listed here must be set as a required attribute in your cognito user
    | pool.
    |
    | When sso_repository_class is set this package will pass a new instance
    | of the the auth provider's user model to the given class's
    | createCognitoUser method. The users model will be hydrated with the given
    | sso_user_attributes before it is passed.
    | This will require the user table has the appropriate fields created. Add
    | these to the data base migration.
    | example: $table->string('given_name', 255)->nullable();
    |
    | error_if_missing_attr will cause the app to through an error if any
    | of the sso_user_attributes are missing from the cognito response making them
    | effectively required.  error_if_missing_attr=false makes them optional
    |
    | sso_groups will copy the user pool group field to a field in the user table
    | this requires a cognito_groups field in the user table also.  multiple groups
    | will be comma delimited.
    |
    */

    'sso'                   => env('SSO', false),
    'sso_repository_class'  => null,
    'sso_user_attributes'   => [
        'name',
        'email',
    ],
    'error_if_missing_attr' => true,
    'sso_groups'            => env('SSO_GROUPS', false),
];
