<?php

namespace WSE\Opauth;

use SilverStripe\Control\Controller;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\LoginForm;

class LoginHandler extends RequestHandler
{
    /**
     * @var Authenticator
     */
    protected $authenticator;

    /**
     * @var array
     * @config
     */
    private static $url_handlers = [
        '' => 'login',
    ];

    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'login',
        'loginForm'
    ];

    /**
     * @var string Called link on this handler
     */
    private $link;

    /**
     * @param string $link The URL to recreate this request handler
     * @param Authenticator $authenticator The authenticator to use
     */
    public function __construct(string $link, Authenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    /**
     * Return a link to this request handler.
     * The link returned is supplied in the constructor
     *
     * @param null|string $action
     * @return string
     */
    public function link($action = null)
    {
        if ($action) {
            return Controller::join_links($this->link, $action);
        }

        return $this->link;
    }

    /**
     * URL handler for the log-in screen
     *
     * @return array
     */
    public function login()
    {
        return [
            'Form' => $this->loginForm(),
        ];
    }

    /**
     * Return the LoginForm
     *
     * @return LoginForm
     */
    public function LoginForm()
    {
        return OpauthLoginForm::create(
            $this,
            'LoginForm'
        );
    }

}
