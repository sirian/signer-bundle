<?php

namespace Sirian\SignerBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class SignedRequestFactory implements SecurityFactoryInterface
{
    public function getKey()
    {
        return 'sirian_signed_request';
    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.sirian_signer.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('sirian_signer.authentication.provider'))
            ->replaceArgument(1, new Reference($userProvider))
        ;

        $listenerId = 'security.authentication.listener.sirian_signer.'.$id;
        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('sirian_signer.authentication.listener'));

        $listener
            ->replaceArgument(3, isset($config['success_handler']) ? new Reference($config['success_handler']) : null)
            ->replaceArgument(4, isset($config['failure_handler']) ? new Reference($config['failure_handler']) : null)
            ->replaceArgument(5, $config);
        ;

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        $builder
            ->children()
                ->scalarNode('signed_login_parameter')->defaultValue('signed_login')->end()
                ->scalarNode('intention')->defaultValue('authenticate')->end()
                ->scalarNode('success_handler')->end()
                ->scalarNode('failure_handler')->end()
        ;
    }
}
