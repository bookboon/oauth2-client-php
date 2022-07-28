<?php

namespace Bookboon\OauthClient;

use Symfony\Component\Security\Core\User\UserInterface;

class AuthServiceUser implements UserInterface
{
    private string $userId = '';
    private string $username = '';
    private array $roles = [];
    private ?string $token = null;
    private ?string $email = null;

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
        return "";
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

    public function getToken(): ?string
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

    /**
     * @return void
     */
    public function eraseCredentials()
    {
    }

    /**
     * @param string $userId
     * @return AuthServiceUser
     */
    public function setUserId(string $userId): AuthServiceUser
    {
        $this->userId = $userId;
        return $this;
    }

    /**
     * @param string $username
     * @return AuthServiceUser
     */
    public function setUsername(string $username): AuthServiceUser
    {
        $this->username = $username;
        return $this;
    }

    /**
     * @param array $roles
     * @return AuthServiceUser
     */
    public function setRoles(array $roles): AuthServiceUser
    {
        $this->roles = $roles;
        return $this;
    }

    /**
     * @param string $token
     * @return AuthServiceUser
     */
    public function setToken(string $token): AuthServiceUser
    {
        $this->token = $token;
        return $this;
    }

    /**
     * @param string|null $email
     * @return AuthServiceUser
     */
    public function setEmail(?string $email): AuthServiceUser
    {
        $this->email = $email;
        return $this;
    }
}
