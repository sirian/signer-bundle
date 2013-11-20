<?php

namespace Sirian\SignerBundle\Security\Authentication\Provider;

use Sirian\SignerBundle\Security\Authentication\Token\SignedRequestToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class SignedRequestProvider implements AuthenticationProviderInterface
{
    protected $userChecker;
    protected $provider;

    public function __construct(UserChecker $userChecker, UserProviderInterface $provider)
    {
        $this->userChecker = $userChecker;
        $this->provider = $provider;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof SignedRequestToken;
    }

    public function authenticate(TokenInterface $token)
    {
        /**
         * @var SignedRequestToken $token
         */
        $user = $this->provider->loadUserByUsername($token->getUsername());

        if (!$user instanceof UserInterface) {
            throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
        }

        $token = new SignedRequestToken($user->getUsername(), $user->getRoles());

        $token->setUser($user);
        $token->setAuthenticated(true);

        $this->userChecker->checkPostAuth($user);

        return $token;
    }
}
