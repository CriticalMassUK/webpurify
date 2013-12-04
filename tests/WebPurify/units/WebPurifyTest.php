<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

abstract class WebPurifyTest extends PHPUnit_Framework_TestCase
{

    protected $webPurify;

    /* helpers */

    public function setUp()
    {
        $this->webPurify = $this
            ->getMockBuilder($this->getMockClassName())
            ->setConstructorArgs(array(WEB_PURIFY_API_KEY))
            ->setMethods(array('http'))
            ->getMock();

        $mockFileName = $this->getMockFileName();
        if ($mockFileName) {
            $this->webPurify
                ->expects($this->any())
                ->method('http')
                ->will($this->returnValue(
                    file_get_contents($mockFileName)
                ));
        }
    }

    protected function getMockClassName()
    {
        return preg_replace('/Test$/i', '', get_class($this));
    }

    protected function getMockFileName()
    {
        $classNamespace = explode('\\', get_class($this)); 
        $className = end($classNamespace); 

        return realpath(sprintf(
            '%s%s/%s.xml',
            WEB_PURIFY_MOCK_RESPONSES_DIR,
            $className,
            $this->getName()
        ));
    }
}
