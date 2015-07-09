<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

class WebPurifyImageTest extends WebPurifyTest
{

    public function testImgAccount()
    {
        $remaining = $this->webPurify->imgAccount();
        $this->assertSame(151, $remaining);
    }

    public function testImgCheck()
    {
        $imageId = $this->webPurify->imgCheck('http://farm1.static.flickr.com/30/59010752_4d16aca1ec_o.jpg');
        $this->assertSame('7de93bc200ff21a26da6ddb115506e82', $imageId);
    }

    public function testImgStatusApproved()
    {
        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertTrue($status);
    }

    public function testImgStatusDeclined()
    {
        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertFalse($status);
    }

    public function testImgStatusPending()
    {
        $status = $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
        $this->assertNull($status);
    }

    /**
     * @expectedException \WebPurify\WebPurifyException
     */
    public function testImgStatusInvalid()
    {
        $this->webPurify->imgStatus('7de93bc200ff21a26da6ddb115506e82');
    }
}
