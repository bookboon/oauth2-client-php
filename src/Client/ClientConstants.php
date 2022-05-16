<?php

namespace Bookboon\OauthClient\Client;

class ClientConstants
{
    const HTTP_HEAD = 'HEAD';
    const HTTP_GET = 'GET';
    const HTTP_POST = 'POST';
    const HTTP_DELETE = 'DELETE';
    const HTTP_PUT = 'PUT';

    const CONTENT_TYPE_JSON = 'application/json';
    const CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded';

    const API_PROTOCOL = 'https';
    const API_HOST = 'bookboon.com';
    const API_PATH = '/api';

    const VERSION = 'Bookboon-PHP/3.3';
}
