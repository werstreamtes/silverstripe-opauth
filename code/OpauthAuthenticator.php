<?php

namespace WSE\Opauth;

use Opauth;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;

/**
 * Base authenticator for SilverStripe Opauth module.
 * @author Will Morgan <@willmorgan>
 * @author Dan Hensby <@dhensby>
 * @copyright Copyright (c) 2013, Better Brief LLP
 */
class OpauthAuthenticator implements Authenticator
{

    use Configurable;

    /**
     * @var Opauth Persistent Opauth instance.
     */
    private static $opauth;

    /**
     * get_enabled_strategies
     * @return array Enabled strategies set in _config
     */
    public static function get_enabled_strategies(): array
    {
        $strategyConfig =  self::config()->opauth_settings['Strategy'];
        return array_keys($strategyConfig);
    }

    /**
     * get_opauth_config
     * @param array Any extra overrides
     * @return array Config for use with Opauth
     */
    public static function get_opauth_config($mergeConfig = []): array
    {
        $config = self::config();
        return array_merge([
            'path' => OpauthController::get_path(),
            'callback_url' => OpauthController::get_callback_path(),
        ], $config->opauth_settings, $mergeConfig);
    }

    /**
     * opauth
     * @param boolean $autoRun Should Opauth auto run? Default: false
     * @param array $config
     * @return Opauth The Opauth instance. Isn't it easy to typo this as Opeth?
     */
    public static function opauth(bool $autoRun = false, array $config = []): Opauth
    {
        if (!isset(self::$opauth)) {
            self::$opauth = new Opauth(self::get_opauth_config($config), $autoRun);
        }
        return self::$opauth;
    }

    /**
     * get_strategy_segment
     * Works around Opauth's weird URL scheme - GoogleStrategy => /google/
     * @param $strategy
     * @return string
     */
    public static function get_strategy_segment($strategy): string
    {
        return preg_replace('/(strategy)$/', '', strtolower($strategy));
    }

    /**
     * @param Controller $controller
     * @return OpauthLoginForm
     */
    public static function get_login_form(Controller $controller): OpauthLoginForm
    {
        return new OpauthLoginForm($controller, 'LoginForm');
    }

    /**
     * Get the name of the authentication method
     *
     * @return string Returns the name of the authentication method.
     */
    public static function get_name(): string
    {
        return _t(__class__ . '.TITLE', 'Social Login');
    }

    public function supportedServices(): int
    {
        return Authenticator::LOGIN;
    }

    public function getLoginHandler($link)
    {
        return LoginHandler::create($link, $this);
    }

    public function getLogOutHandler($link)
    {
        // TODO: Implement getLogOutHandler() method.
    }

    public function getChangePasswordHandler($link)
    {
        // TODO: Implement getChangePasswordHandler() method.
    }

    public function getLostPasswordHandler($link)
    {
        // TODO: Implement getLostPasswordHandler() method.
    }

    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        // TODO: Implement authenticate() method.
    }

    public function checkPassword(Member $member, $password, ValidationResult &$result = null)
    {
        // TODO: Implement checkPassword() method.
    }
}
