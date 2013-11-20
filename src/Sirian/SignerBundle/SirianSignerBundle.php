<?php

namespace Sirian\SignerBundle;

use Sirian\SignerBundle\DependencyInjection\Security\Factory\SignedRequestFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SirianSignerBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new SignedRequestFactory());
    }

}
