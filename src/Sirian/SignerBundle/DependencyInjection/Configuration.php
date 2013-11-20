<?php

namespace Sirian\SignerBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration  implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $root = $treeBuilder->root('sirian_signer');

        $root
            ->children()
                ->scalarNode('secret')->isRequired()->end()
                ->scalarNode('algorithm')->defaultValue('sha256')->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
