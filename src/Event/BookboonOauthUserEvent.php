<?php

namespace Bookboon\OauthClient\Event;

use Bookboon\OauthClient\BookboonResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

class BookboonOauthUserEvent
{
    public function __construct(
        protected Request $request,
        protected BookboonResourceOwner $resourceOwner,
        protected AccessToken $accessToken,
        protected ?UserInterface $user = null,
    )
    {
    }

    /**
     * @return Request
     */
    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * @param Request $request
     */
    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    /**
     * @return BookboonResourceOwner
     */
    public function getResourceOwner(): BookboonResourceOwner
    {
        return $this->resourceOwner;
    }

    /**
     * @param BookboonResourceOwner $resourceOwner
     */
    public function setResourceOwner(BookboonResourceOwner $resourceOwner): void
    {
        $this->resourceOwner = $resourceOwner;
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken(): AccessToken
    {
        return $this->accessToken;
    }

    /**
     * @param AccessToken $accessToken
     */
    public function setAccessToken(AccessToken $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return UserInterface|null
     */
    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    /**
     * @param UserInterface|null $user
     */
    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }
}
