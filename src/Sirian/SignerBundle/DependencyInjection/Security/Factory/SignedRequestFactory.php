<?php

namespace Sirian\SignerBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class SignedRequestFactory extends AbstractFactory
{
    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $providerId = 'sirian_signer.authentication.provider.' . $id;

        $container
            ->setDefinition($providerId, new DefinitionDecorator('sirian_signer.authentication.provider'))
            ->addArgument(new Reference($userProviderId))
        ;

        return $providerId;
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $this->addOption('require_previous_session', false);
        parent::addConfiguration($node);
    }

    protected function getListenerId()
    {
        return 'sirian_signer.authentication.listener';
    }

    public function getKey()
    {
        return 'sirian_signed_request';
    }

    public function getPosition()
    {
        return 'http';
    }
}
