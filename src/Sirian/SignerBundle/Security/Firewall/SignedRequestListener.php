<?php

namespace Sirian\SignerBundle\Security\Firewall;

use Sirian\Signer\Decoder;
use Sirian\Signer\ExpiredException;
use Sirian\Signer\SignException;
use Sirian\SignerBundle\Security\Authentication\Token\SignedRequestToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class SignedRequestListener implements ListenerInterface
{
    private $decoder;
    private $securityContext;
    private $authenticationManager;
    private $options;

    public function __construct(Decoder $decoder, SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, array $options = [])
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->options = array_merge([
            'signed_login_parameter' => 'signed_login',
            'intention' => 'signed_login',
            'success_handler' => null,
            'failure_handler' => null,
        ], $options);
        $this->decoder = $decoder;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (!$request->query->has($this->options['signed_login_parameter'])) {
            return;
        }

        try {
            $token = $this->createToken($request);
            $token = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($token);
        } catch (AuthenticationException $e) {
            $this->securityContext->setToken(null);

            $failureHandler = $this->options['failure_handler'];
            if ($failureHandler instanceof AuthenticationFailureHandlerInterface) {
                $response = $failureHandler->onAuthenticationFailure($request, $e);
                if ($response instanceof Response) {
                    $event->setResponse($response);
                } elseif (null !== $response) {
                    throw new \UnexpectedValueException(sprintf('The %s::onAuthenticationFailure method must return null or a Response object', get_class($this->failureHandler)));
                }
            }

            return;
        }

        $successHandler = $this->options['success_handler'];
        if ($successHandler instanceof AuthenticationSuccessHandlerInterface) {
            $response = $successHandler->onAuthenticationSuccess($request, $token);
            if ($response instanceof Response) {
                $event->setResponse($response);
            } elseif (null !== $response) {
                throw new \UnexpectedValueException(sprintf('The %s::onAuthenticationSuccess method must return null or a Response object', get_class($this->successHandler)));
            }
        }
    }

    public function createToken(Request $request)
    {
        try {
            $data = $this
                ->decoder
                ->decode($request->query->get($this->options['signed_login_parameter']), $this->options['intention'])
                ->getData()
            ;
        } catch (ExpiredException $e) {
            throw new AuthenticationException('Signed request expired', 0, $e);
        } catch (SignException $e) {
            throw new AuthenticationException('Invalid signed request', 0, $e);
        }

        if (!isset($data['username'])) {
            throw new AuthenticationException('Invalid signed request - username required');
        }

        $token = new SignedRequestToken($data['username']);
        $token->setSignedData($data);

        return $token;
    }
}
