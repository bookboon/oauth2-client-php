<?php

namespace Bookboon\OauthClient\Event;

use Symfony\Component\HttpFoundation\Request;

class BookboonOauthOptionsEvent
{
    public function __construct(
        protected Request $request,
        protected ?array $options = null
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
     * @return array|null
     */
    public function getOptions(): ?array
    {
        return $this->options;
    }

    /**
     * @param array|null $options
     */
    public function setOptions(?array $options): void
    {
        $this->options = $options;
    }
}
