<?php

namespace Bookboon\OauthClient;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;

class BookboonResourceOwner implements ResourceOwnerInterface
{
    use ArrayAccessorTrait;

    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param array  $response
     */
    public function __construct(array $response = [])
    {
        $this->response = $response;
    }
    /**
     * Get resource owner id
     *
     * @return string
     */
    public function getId()
    {
        return $this->getValueByKey($this->response, 'user.id') ??
            $this->getValueByKey($this->response, 'application.id');
    }

    /**
     * @return array
     */
    public function getApplication()
    {
        return $this->getValueByKey($this->response, 'application');
    }

    /**
     * Get resource owner name
     *
     * @return string
     */
    public function getName()
    {
        return $this->getValueByKey($this->response, 'user.name');
    }

    /**
     * @return string|null
     */
    public function getEmail() : ?string
    {
        return $this->getValueByKey($this->response, 'user.email');
    }

    /**
     * @return array
     */
    public function getRoles()
    {
        return $this->getValueByKey($this->response, 'user.roles');
    }

    public function getBlobId()
    {
        return $this->getValueByKey($this->response, 'user.blobId');
    }

    public function getOrganisationId()
    {
        return $this->getValueByKey($this->response, 'application.organisation.id');
    }

    public function getApplicationId()
    {
        return $this->getValueByKey($this->response, 'application.id');
    }

    /**
     * @return array<string, array<array{objectId: string, name: string, totalUsers?: float, defaultGroup?: string}>>
     */
    public function getObjectAccess()
    {
        return $this->getValueByKey($this->response, 'user.objectAccess', []);
    }

    /**
     * @return string[]
     */
    public function getObjectAccessApplication()
    {
        $applications = $this->getValueByKey($this->response, 'user.objectAccess.application', []);

        $applicationIds = array_map(
            function ($app) {
                return $app['id'];
            },
            $applications
        );

        $applicationIds[] = $this->getId();

        return $applicationIds;
    }

    /**
     * @return array
     */
    public function getScopes()
    {
        return $this->getValueByKey($this->response, 'grantedScopes');
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        $response = $this->response;

        /* Symfony roles must be prepended with "ROLE_" */
        $response['user']['roles'] = array_map(
            function ($role) {
                return "ROLE_$role";
            },
            $response['user']['roles']
        );

        return $response;
    }
}
