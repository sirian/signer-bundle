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
    }

    protected function attemptAuthentication(Request $request)
    {
        try {
            $data = $this
                ->decoder
                ->decode($request->query->get('signed_request', ''), 'authenticate')
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

        return $this->authenticationManager->authenticate($token);
    }
}
