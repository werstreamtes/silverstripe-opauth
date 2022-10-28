<?php

namespace WSE\Opauth;

use Opauth;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

/**
 * Base authenticator for SilverStripe Opauth module.
 * @author Will Morgan <@willmorgan>
 * @author Dan Hensby <@dhensby>
 * @copyright Copyright (c) 2013, Better Brief LLP
 */
class OpauthAuthenticator extends MemberAuthenticator
{

    private static
        /**
         * @var Opauth Persistent Opauth instance.
         */
        $opauth;

    protected static $config = [];

    public function __construct()
    {
        self::$config = Config::inst()->get(__CLASS__, 'opauth_settings');
    }

    /**
     * get_enabled_strategies
     * @return array Enabled strategies set in _config
     */
    public static function get_enabled_strategies(): array
    {
        $strategyConfig = self::$config['Strategy'];
        return array_keys($strategyConfig);
    }

    /**
     * get_opauth_config
     * @param array Any extra overrides
     * @return array Config for use with Opauth
     */
    public static function get_opauth_config($mergeConfig = []): array
    {
        return array_merge(
            [
                'path' => OpauthController::get_path(),
                'callback_url' => OpauthController::get_callback_path(),
            ],
            self::$config['Strategy'],
            $mergeConfig
        );
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
        return _t('OpauthAuthenticator.TITLE', 'Social Login');
    }

}
