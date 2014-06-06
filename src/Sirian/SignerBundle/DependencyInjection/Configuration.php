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
                ->arrayNode('filters')
                    ->defaultValue(['json', 'gz', 'base64'])
                    ->beforeNormalization()
                        ->ifTrue(function ($v) { return !is_array($v) && !is_null($v); })
                        ->then(function ($v) { return is_bool($v) ? array() : preg_split('/\s*,\s*/', $v); })
                    ->end()
                    ->prototype('scalar')
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
