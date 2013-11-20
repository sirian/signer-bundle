<?php

namespace Sirian\SignerBundle;

use Sirian\Signer\Data;
use Sirian\Signer\Decoder;
use Sirian\Signer\Encoder;

class Manager
{
    private $encoder;
    private $decoder;

    public function __construct(Encoder $encoder, Decoder $decoder)
    {
        $this->encoder = $encoder;
        $this->decoder = $decoder;
    }

    public function encode($data, $intention, \DateTime $expires = null)
    {
        $signData = new Data();
        $signData
            ->setData($data)
            ->setIntention($intention)
            ->setExpires($expires)
        ;

        return $this->encoder->encode($signData);
    }

    public function decode($string, $intention)
    {
        return $this->decoder->decode($string, $intention);
    }
}
