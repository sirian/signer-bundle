<?php

namespace Sirian\SignerBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken as BaseAbstractToken;

class SignedRequestToken extends BaseAbstractToken
{
    protected $signedData;

    public function __construct($username, $roles = array())
    {
        parent::__construct($roles);

        $this->setUser($username);
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getSignedData()
    {
        return $this->signedData;
    }

    public function setSignedData($data)
    {
        $this->signedData = $data;

        return $this;
    }

    public function getCredentials()
    {
        return '';
    }
}
