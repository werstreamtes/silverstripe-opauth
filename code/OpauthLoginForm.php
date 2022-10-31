<?php

namespace WSE\Opauth;

use InvalidArgumentException;
use LogicException;
use OpauthStrategy;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Security\LoginForm;

/**
 * OpauthLoginForm
 * The form presented to users for signing in with an Opauth strategy.
 * Not a form, rather a gateway that works by taking enabled strategies and
 * displaying a button to start the OAuth process with that strategy provider.
 * @author Will Morgan <@willmorgan>
 * @author Dan Hensby <@dhensby>
 * @copyright Copyright (c) 2013, Better Brief LLP
 */
class OpauthLoginForm extends LoginForm
{

    public $authenticator_class = 'WSE\\Opauth\\OpauthAuthenticator';

    public function __construct($controller, $name)
    {
        parent::__construct($controller, $name, $this->getFormFields(), $this->getFormActions());
        $this->configureBackURL();
    }

    /**
     * @return array All enabled strategies from config
     */
    public function getStrategies(): array
    {
        return OpauthAuthenticator::get_enabled_strategies();
    }

    /**
     * Handle any backURL. Uses sessions as state gets lost through OAuth flow.
     * Use the same session key as MemberLoginForm for x-compat.
     */
    public function configureBackURL()
    {
        if ($backURL = $this->controller->getRequest()->param('BackURL')) {
            $this->controller->getRequest()->getSession()->set('BackURL', $backURL);
        }
    }

    /**
     * Ensure AuthenticationMethod is set to tell Security which form to process
     * Very important for multi authenticator form setups.
     * @return FieldList
     */
    protected function getFormFields(): FieldList
    {
        $fields = FieldList::create(
            HiddenField::create('AuthenticationMethod', null, $this->authenticator_class, $this)
        );
        $this->extend('updateFormFields', $fields);
        return $fields;
    }

    /**
     * Provide an action button to be clicked per strategy.
     * @return FieldList
     */
    protected function getFormActions(): FieldList
    {
        $actions = FieldList::create();
        foreach ($this->getStrategies() as $strategyClass) {
            $fa = FormAction::create('handleStrategy' . $strategyClass, $strategyClass);
            $actions->push($fa);
        }

        $this->extend('updateFormActions', $actions);
        return $actions;
    }

    /**
     * Global endpoint for handleStrategy - all strategy actions point here.
     * @param string $funcName The bound function name from addWrapperMethod
     * @return HTTPResponse
     */
    public function handleStrategy(string $funcName): HTTPResponse
    {
        // Trim handleStrategy from the function name:
        $strategy = $funcName . 'Strategy';

        // Check the strategy is good
        if (!class_exists($strategy) || $strategy instanceof OpauthStrategy) {
            throw new InvalidArgumentException('Opauth strategy ' . $strategy . ' was not found or is not a valid strategy');
        }

        return $this->controller->redirect(
            Controller::join_links(
                OpauthController::get_path(),
                OpauthAuthenticator::get_strategy_segment($strategy)
            )
        );
    }

    public function hasMethod($method)
    {
        if (strpos($method, 'handleStrategy') === 0) {
            $providers = $this->getStrategies();
            $name = substr($method, strlen('handleStrategy'));

            if (in_array($name, $providers)) {
                return true;
            }
        }

        return parent::hasMethod($method);
    }

    public function __call($method, $args)
    {
        if (strpos($method, 'handleStrategy') === 0) {
            $providers = $this->getStrategies();
            $name = substr($method, strlen('handleStrategy'));

            if (in_array($name, $providers)) {
                return $this->handleStrategy($name);
            }
        }

        return parent::__call($method, $args);
    }

    /**
     * The authenticator name, used in templates
     * @return string
     */
    public function getAuthenticatorName(): string
    {
        return OpauthAuthenticator::get_name();
    }

}
