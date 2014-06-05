<?php

namespace Sirian\SignerBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class FilterConfigurationPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        $registry = $container->getDefinition('sirian_signer.filter_registry');
        foreach ($container->findTaggedServiceIds('sirian_signer.filter') as $id => $service) {
            $registry->addMethodCall('add', [new Reference($id)]);
        }
    }
}
