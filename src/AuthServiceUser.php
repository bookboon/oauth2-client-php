<?php

namespace Bookboon\OauthClient;

use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AuthServiceUser implements UserInterface
{
    protected string $userId = '';
    protected string $username = '';
    protected array $roles = [];
    protected ?string $email = null;
    protected ?AccessTokenInterface $token = null;
    protected ?string $applicationId  = null;
    protected ?string $organisationId  = null;
    protected ?string $blobId = null;
    protected string $thumbnail = '';
    protected array $objectAccess = [];

    /**
     * @return string[]
     */
    public function getRoles(): array
    {
        return array_map(
            static function ($role) {
                return strpos($role, 'ROLE_') === 0 ? $role : 'ROLE_' . strtoupper($role);
            },
            $this->roles
        );
    }

    /**
     * Returns the identifier for this user (e.g. its username or email address).
     */
    public function getUserIdentifier(): string
    {
        return $this->getIdentifier();
    }

    public function getThumbnail(): string
    {
        return $this->thumbnail;
    }

    public function getId(): string
    {
        return $this->userId;
    }

    public function getName(): string
    {
        return $this->getUsername();
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getAccessToken(): ?AccessTokenInterface
    {
        return $this->token;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getIdentifier(): string
    {
        return $this->getUsername();
    }

    public function getPassword(): string
    {
        return '';
    }

    public function getSalt(): string
    {
        return '';
    }

    public function getOrganisationId(): ?string
    {
        return $this->organisationId;
    }

    public function getApplicationId(): ?string
    {
        return $this->applicationId;
    }

    public function getBlobId(): ?string
    {
        return $this->blobId;
    }

    public function getObjectAccess(): array
    {
        return $this->objectAccess;
    }

    public function eraseCredentials(): void
    {
    }

    public function setUserId(string $userId): static
    {
        $this->userId = $userId;
        return $this;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;
        return $this;
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;
        return $this;
    }
    public function setAccessToken(?AccessTokenInterface $token): static
    {
        $this->token = $token;
        return $this;
    }

    public function setOrganisationId(?string $organisationId): static
    {
        $this->organisationId = $organisationId;
        return $this;
    }

    public function setApplicationId(?string $applicationId): static
    {
        $this->applicationId = $applicationId;
        return $this;
    }

    public function setEmail(?string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function setBlobId(?string $blobId): static
    {
        $this->blobId = $blobId;
        return $this;
    }

    public function setObjectAccess(array $objectAccess): static
    {
        $this->objectAccess = $objectAccess;
        return $this;
    }

    public function setThumbnail(string $thumbnail): static
    {
        $this->thumbnail = $thumbnail;
        return $this;
    }
}
