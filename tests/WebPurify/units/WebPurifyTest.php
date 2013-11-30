<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

abstract class WebPurifyTest extends PHPUnit_Framework_TestCase
{
    protected $webPurify;

    /* helpers */

    protected function mockHTTP($filename)
    {
        $this->webPurify
            ->expects($this->any())
            ->method('http')
            ->will($this->returnValue(
                file_get_contents(WEB_PURIFY_MOCK_RESPONSES_DIR . $filename)
            ));
    }
}
