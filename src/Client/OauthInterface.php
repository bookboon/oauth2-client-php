<?php

namespace Bookboon\OauthClient\Client;

use Bookboon\OauthClient\Client\Oauth\OauthGrants;
use Bookboon\OauthClient\Exception\ApiAuthenticationException;
use Bookboon\OauthClient\Exception\ApiInvalidStateException;
use Bookboon\OauthClient\Exception\UsageException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;

interface OauthInterface
{
    /**
     * @param array $options
     * @param string $type
     * @return AccessTokenInterface
     * @throws ApiAuthenticationException
     * @throws UsageException
     */
    public function requestAccessToken(
        array $options = [],
        string $type = OauthGrants::AUTHORIZATION_CODE
    ) : AccessTokenInterface;

    /**
     * @param AccessTokenInterface $accessToken
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    public function refreshAccessToken(AccessTokenInterface $accessToken) : AccessTokenInterface;

    /**
     * @return string
     */
    public function generateState(): string;

    /**
     * @param string $stateParameter
     * @param string $stateSession
     * @return boolean
     * @throws ApiInvalidStateException
     */
    public function isCorrectState(string $stateParameter, string $stateSession) : bool;

    /**
     * @param array $options
     * @return string
     */
    public function getAuthorizationUrl(array $options = []): string;
}
