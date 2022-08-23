<?php

namespace Bookboon\OauthClient;

use Bookboon\OauthClient\Event\BookboonOauthOptionsEvent;
use Bookboon\OauthClient\Event\BookboonOauthUserEvent;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use RuntimeException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class Authenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    public const AUTH_PROVIDER = 'auth-service';
    public const FIRST_REFERER = 'first_referer';
    public const REMEMBERED_REDIRECT = 'remembered_redirect';

    public function __construct(
        protected ClientRegistry $_clientRegistry,
        protected RouterInterface $_router,
        protected EventDispatcherInterface $_dispatcher,
        protected string $rejectionRoute = '',
        protected string $acceptanceRoute = '',
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') == 'auth_check';
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->_clientRegistry->getClient(self::AUTH_PROVIDER);
        $accessToken = $this->fetchAccessToken($client);
        /** @var BookboonResourceOwner $resourceOwner */
        $resourceOwner = $client->fetchUserFromToken($accessToken);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $resourceOwner, $request) {
                $event = new BookboonOauthUserEvent($request, $resourceOwner, $accessToken);
                $this->_dispatcher->dispatch($event);
                $user = $event->getUser();

                if ($user === null) {
                    $user = (new AuthServiceUser())
                        ->setUserId($resourceOwner->getId())
                        ->setUsername($resourceOwner->getName())
                        ->setRoles($resourceOwner->getRoles())
                        ->setEmail($resourceOwner->getEmail())
                        ->setToken($accessToken->getToken());
                }

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $rememberedRedirect = $request->getSession()->get(self::REMEMBERED_REDIRECT);

        if ($rememberedRedirect) {
            return new RedirectResponse($rememberedRedirect);
        }

        $url = '/';

        if ($this->acceptanceRoute !== '') {
            $url = $this->_router->generate($this->acceptanceRoute);
        }

        return new RedirectResponse($url);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($this->rejectionRoute !== '') {
            return new RedirectResponse($this->_router->generate($this->rejectionRoute));
        }

        return new Response("access denied", 401);
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        if ($request->isXmlHttpRequest()) {
            return new JsonResponse(
                [
                    'status' => Response::HTTP_FORBIDDEN,
                    'message' => 'Unauthorized, needs to revalidate',
                    'command' => 'refresh'
                ],
                403
            );
        }

        $event = new BookboonOauthOptionsEvent($request, []);
        $this->_dispatcher->dispatch($event);
        $options = $event->getOptions();

        if (str_starts_with($request->getRequestUri(), '/reader/data')) {
            return new Response('', Response::HTTP_FORBIDDEN);
        }

        $request->getSession()->set(self::REMEMBERED_REDIRECT, $request->getRequestUri());
        $request->getSession()->set(self::FIRST_REFERER, $request->headers->get('referer'));

        $retryCounter = (int) $request->query->get('retry', -1);
        $options['retry'] = ++$retryCounter;

        if ($options['retry'] > 3) {
            throw new RuntimeException("retries have been exhausted");
        }

        return $this->_clientRegistry->getClient("auth-service")->redirect([], $options);
    }
}
