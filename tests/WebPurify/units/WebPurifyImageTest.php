<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

class WebPurifyImageTest extends WebPurifyTest
{

    public function setUp()
    {
        $this->webPurify = $this
            ->getMockBuilder('WebPurify\WebPurifyImage')
            ->setConstructorArgs(array(WEB_PURIFY_API_KEY))
            ->setMethods(array('http'))
            ->getMock();
    }

    /* */

    public function testImgAccount()
    {
        $this->mockHTTP('image/imgaccount.xml');

        $remaining = $this->webPurify->imgAccount();
        $this->assertEquals(151, $remaining);
    }

    public function testImgCheck()
    {
        $this->mockHTTP('image/imgcheck.xml');

        $imageId = $this->webPurify->imgCheck('http://farm1.static.flickr.com/30/59010752_4d16aca1ec_o.jpg');
        $this->assertEquals('7de93bc200ff21a26da6ddb115506e82', $imageId);
    }

    public function testImgStatusApproved()
    {
        $this->mockHTTP('image/imgstatus_approved.xml');

        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertTrue($status);
    }

    public function testImgStatusDeclined()
    {
        $this->mockHTTP('image/imgstatus_declined.xml');

        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertFalse($status);
    }

    public function testImgStatusPending()
    {
        $this->mockHTTP('image/imgstatus_pending.xml');

        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertNull($status);
    }
}