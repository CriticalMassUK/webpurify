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

    public function testApiKey() {
        $this->webPurify->setApiKey('asdfghjkl');
        $this->assertEquals('asdfghjkl', $this->webPurify->getApiKey());
    }

    public function testUseSSL() {
        $this->webPurify->setUseSSL(false);
        $this->assertFalse($this->webPurify->getUseSSL());

        $this->webPurify->setUseSSL(true);
        $this->assertTrue($this->webPurify->getUseSSL());
    }

    public function testSSLVerifyPeer() {
        $this->webPurify->setSSLVerifyPeer(false);
        $this->assertFalse($this->webPurify->getSSLVerifyPeer());

        $this->webPurify->setSSLVerifyPeer(true);
        $this->assertTrue($this->webPurify->getSSLVerifyPeer());
    }

    public function testUserAgent() {
        $this->webPurify->setUserAgent('User agent');
        $this->assertEquals('User agent', $this->webPurify->getUserAgent());
    }

    public function testSandbox() {
        $this->webPurify->setSandbox(false);
        $this->assertFalse($this->webPurify->getSandbox());

        $this->webPurify->setSandbox(true);
        $this->assertTrue($this->webPurify->getSandbox());
    }

    public function testEndPointDomain() {
        $this->webPurify->setEndPointDomain('api1.webpurify.com');
        $this->assertEquals(
            'api1.webpurify.com', 
            $this->webPurify->getEndPointDomain()
        );

        $this->webPurify->setEndPointDomain('api1-eu.webpurify.com');
        $this->assertEquals(
            'api1-eu.webpurify.com',
            $this->webPurify->getEndPointDomain()
        );
    }
}
