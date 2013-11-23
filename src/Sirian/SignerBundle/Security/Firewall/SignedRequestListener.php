<?php

namespace Sirian\SignerBundle\Security\Firewall;

use Sirian\Signer\Decoder;
use Sirian\Signer\ExpiredException;
use Sirian\Signer\SignException;
use Sirian\SignerBundle\Security\Authentication\Token\SignedRequestToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;

class SignedRequestListener extends AbstractAuthenticationListener
{
    /**
     * @var Decoder
     */
    protected $decoder;

    public function setDecoder($decoder)
    {
        $this->decoder = $decoder;

        return $this;
    }

    protected function requiresAuthentication(Request $request)
    {
        return $request->query->has($this->options['signed_login_parameter']);
    }

    public function attemptAuthentication(Request $request)
    {
        try {
            $data = $this
                ->decoder
                ->decode($request->query->get($this->options['signed_login_parameter']), 'authenticate')
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

        $query = $request->query->all();
        unset($query[$this->options['signed_login_parameter']]);
        $request->server->set('QUERY_STRING', http_build_query($query));
        $request->attributes->set($this->options['target_path_parameter'], $request->getUri());

        return $this->authenticationManager->authenticate($token);
    }
}
