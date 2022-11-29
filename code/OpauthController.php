<?php

namespace WSE\Opauth;

use InvalidArgumentException;
use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBHTMLText;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * OpauthController
 * Wraps around Opauth for handling callbacks.
 * The SS equivalent of "index.php" and "callback.php" in the Opauth package.
 * @author Will Morgan <@willmorgan>
 * @author Dan Hensby <@dhensby>
 * @copyright Copyright (c) 2013, Better Brief LLP
 */
class OpauthController extends ContentController
{

    private static
        $allowed_actions = [
        'index',
        'finished',
        'profilecompletion',
        'RegisterForm',
    ],
        $url_handlers = [
        'finished' => 'finished',
    ];

    /**
     * Bitwise indicators to extensions what sort of action is happening
     */
    const
        /**
         * LOGIN = already a user with an OAuth ID
         */
        AUTH_FLAG_LOGIN = 2,
        /**
         * LINK = already a user, linking a new OAuth ID
         */
        AUTH_FLAG_LINK = 4,
        /**
         * REGISTER = new user, linking OAuth ID
         */
        AUTH_FLAG_REGISTER = 8;

    protected
        $registerForm;

    /**
     * Fake a PageController by using that class as a failover
     */
    public function __construct($dataRecord = null)
    {
        if (class_exists('\PageController')) {
            $dataRecord = new \PageController($dataRecord);
        }
        parent::__construct($dataRecord);
    }

    /**
     * This function only catches the request to pass it straight on.
     * Opauth uses the last segment of the URL to identify the auth method.
     * In _routes.yml we enforce a $Strategy request parameter to enforce this.
     * Equivalent to "index.php" in the Opauth package.
     * @param HTTPRequest $request
     * @return HTTPResponse|void
     * @todo: Validate the strategy works before delegating to Opauth.
     */
    public function index(HTTPRequest $request)
    {

        $strategy = $request->param('Strategy');
        $method = $request->param('StrategyMethod');

        if (!isset($strategy)) {
            return Security::permissionFailure($this);
        }

        // If there is no method then we redirect (not a callback)
        if (!isset($method)) {
            // Redirects:
            OpauthAuthenticator::opauth(true, Config::inst()->get('WSE\\Opauth\\OpauthAuthenticator', 'opauth_settings'));
        } else {
            return $this->oauthCallback($request);
        }
    }

    /**
     * This is executed when the Oauth provider redirects back to us
     * Opauth handles everything sent back in this request.
     */
    protected function oauthCallback(HTTPRequest $request)
    {
        // Set up and run opauth with the correct params from the strategy:
        OpauthAuthenticator::opauth(true, [
            'strategy' => $request->param('Strategy'),
            'action' => $request->param('StrategyMethod'),
        ]);
    }

    /**
     * Equivalent to "callback.php" in the Opauth package.
     * If there is a problem with the response, we throw an HTTP error.
     * When done validating, we return to the Authenticator continue auth.
     * @param HTTPRequest $request
     * @return HTTPResponse|void|null
     * @throws ValidationException
     */
    public function finished(HTTPRequest $request)
    {

        $session = $request->getSession();
        $opauth = OpauthAuthenticator::opauth(false, Config::inst()->get('WSE\\Opauth\\OpauthAuthenticator', 'opauth_settings'));

        $response = $this->getOpauthResponse();

        if (!$response) {
            $response = [];
        }
        // Clear the response as it is only to be read once (if Session)
        $session->clear('opauth');

        // Handle all Opauth validation in this handy function
        try {
            $this->validateOpauthResponse($opauth, $response);
        } catch (OpauthValidationException $e) {
            return $this->handleOpauthException($e);
        }

        $identity = OpauthIdentity::factory($response);

        $member = $identity->findOrCreateMember();

        // If the member exists, associate it with the identity and log in
        if ($member->isInDB() && $member->validate()->isValid()) {
            if (!$identity->exists()) {
                $identity->write();
                $flag = self::AUTH_FLAG_LINK;
            } else {
                $flag = self::AUTH_FLAG_LOGIN;
            }
        } else {

            $flag = self::AUTH_FLAG_REGISTER;

            // Write the identity
            $identity->write();

            // Even if written, check validation - we might not have full fields
            $validationResult = $member->validate();
            if (!$validationResult->isValid()) {
                // Keep a note of the identity ID
                $session->set('OpauthIdentityID', $identity->ID);
                // Set up the register form before it's output
                $regForm = $this->RegisterForm();
                $regForm->loadDataFrom($member);
                $regForm->setSessionData($member);
                $regForm->getValidator()->validate();
                return $this->redirect($this->Link('profilecompletion'));
            } else {
                $member->extend('onBeforeOpauthRegister');
                $member->write();
                $identity->MemberID = $member->ID;
                $identity->write();
            }
        }
        return $this->loginAndRedirect($member, $identity, $flag);
    }

    /**
     * @param Member $member
     * @param int $mode One or more AUTH_FLAGs.
     * @return HTTPResponse|void|null
     */
    protected function loginAndRedirect(Member $member, $identity, int $mode)
    {

        $session = $this->request->getSession();

        // Back up the BackURL as Member::logIn regenerates the session
        $backURL = $session->get('BackURL');

        // Check if we can log in:
        $canLogIn = $member->canLogIn();

        if (!$canLogIn) {
            $extendedURLs = $this->extend('getCantLoginBackURL', $member, $identity, $canLogIn, $mode);
            if (count($extendedURLs)) {
                $redirectURL = array_pop($extendedURLs);
                $this->redirect($redirectURL, 302);
                return;
            }
            Security::permissionFailure($this, "Login not possible.");
            return;
        }

        // Decide where to go afterwards...
        if (!empty($backURL)) {
            $redirectURL = $backURL;
        } else {
            $redirectURL = Security::config()->default_login_dest;
        }

        $extendedURLs = $this->extend('getSuccessBackURL', $member, $identity, $redirectURL, $mode);

        if (count($extendedURLs)) {
            $redirectURL = array_pop($extendedURLs);
        }

        //$member->logIn();

        /** @var IdentityStore $identityStore */
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, true, $this->request);

        // Clear any identity ID
        $session->clear('OpauthIdentityID');

        // Clear the BackURL
        $session->clear('BackURL');

        return $this->redirect($redirectURL);
    }

    /**
     * @param HTTPRequest|null $request
     * @return DBHTMLText
     */
    public function profilecompletion(HTTPRequest $request = null): DBHTMLText
    {
        if (!$request->getSession()->get('opauth')) {
            Security::permissionFailure($this);
        }
        // Redirect to complete register step by adding in extra info
        return $this->renderWith([
                'OpauthController_profilecompletion',
                'Security_profilecompletion',
                'Page',
            ]
        );
    }

    /**
     * @param HTTPRequest|null $request
     * @param Member|null $member
     * @param $result
     * @return OpauthRegisterForm
     */
    public function RegisterForm(HTTPRequest $request = null, Member $member = null, $result = null): OpauthRegisterForm
    {
        if (!isset($this->registerForm)) {
            $form = new OpauthRegisterForm($this, 'RegisterForm', $result);
            $form->populateFromSources($request, $member, $result);
            // Set manually the form action due to how routing works
            $form->setFormAction(Controller::join_links(
                self::config()->opauth_path,
                'RegisterForm'
            ));
            $this->registerForm = $form;
        } else {
            $this->registerForm->populateFromSources($request, $member, $result);
        }
        return $this->registerForm;
    }

    /**
     * @param $data
     * @param $form
     * @param $request
     * @return HTTPResponse|void|null
     * @throws ValidationException
     */
    public function doCompleteRegister($data, $form, $request)
    {
        $member = new Member();
        $form->saveInto($member);
        $identityID = $request->getSession()->get('OpauthIdentityID');
        $identity = OpauthIdentity::get_by_id($identityID);
        $validationResult = $member->validate();
        $existing = Member::get()->filter('Email', $member->Email)->first();
        $emailCollision = $existing && $existing->exists();
        // If not valid then we have to manually transpose errors to the form
        if (!$validationResult->isValid() || $emailCollision) {
            $errors = $validationResult->getMessages();
            $form->setRequiredFields($errors);
            // Mandatory check on the email address
            if ($emailCollision) {
                $form->addErrorMessage('Email', _t(
                    'OpauthRegisterForm.ERROREMAILTAKEN',
                    'It looks like this email has already been used'
                ), 'required');
            }
            return $this->redirect('profilecompletion');
        } // If valid then write and redirect
        else {
            $member->extend('onBeforeOpauthRegister');
            $member->write();
            $identity->MemberID = $member->ID;
            $identity->write();
            return $this->loginAndRedirect($member, $identity, self::AUTH_FLAG_REGISTER);
        }
    }

    /**
     * Returns the response from the Oauth callback.
     * @return array The response
     */
    protected function getOpauthResponse(): array
    {
        $config = Config::inst()->get('WSE\\Opauth\\OpauthAuthenticator', 'opauth_settings');
        $transportMethod = $config['callback_transport'];
        switch ($transportMethod) {
            case 'session':
                return $this->getResponseFromSession();
            case 'get':
            case 'post':
                return $this->getResponseFromRequest($transportMethod);
            default:
                throw new InvalidArgumentException('Invalid transport method: ' . $transportMethod);
        }
    }

    /**
     * Validates the Oauth response for Opauth.
     * @throws InvalidArgumentException|OpauthValidationException
     */
    protected function validateOpauthResponse($opauth, $response)
    {
        if (!empty($response['error'])) {
            throw new OpauthValidationException('Oauth provider error', 1, $response['error']);
        }

        // Required components within the response
        $this->requireResponseComponents(
            ['auth', 'timestamp', 'signature'],
            $response
        );

        // More required components within the auth section...
        $this->requireResponseComponents(
            ['provider', 'uid'],
            $response['auth']
        );

        $invalidReason = '';

        /**
         * @todo: improve this signature check. it's a bit weak.
         */
        if (!$opauth->validate(
            sha1(print_r($response['auth'], true)),
            $response['timestamp'],
            $response['signature'],
            $invalidReason
        )) {
            throw new OpauthValidationException('Invalid auth response', 3, $invalidReason);
        }
    }

    /**
     * Shorthand for quickly finding missing components and complaining about it
     * @throws InvalidArgumentException|OpauthValidationException
     */
    protected function requireResponseComponents(array $components, $response)
    {
        foreach ($components as $component) {
            if (empty($response[$component])) {
                throw new OpauthValidationException('Required component missing', 2, $component);
            }
        }
    }

    /**
     * @return array|null Opauth response from session
     */
    protected function getResponseFromSession(): ?array
    {
        return $this->request->getSession()->get('opauth');
    }

    /**
     * @param OpauthValidationException $e
     */
    protected function handleOpauthException(OpauthValidationException $e)
    {
        $data = $e->getData();
        $message = '';
        switch ($e->getCode()) {
            case 1: // provider error
                $message = _t(
                    'OpauthLoginForm.OAUTHFAILURE',
                    'There was a problem logging in with {provider}.',
                    [
                        'provider' => $data['provider'],
                    ]
                );
                break;
            case 2: // validation error
            case 3: // invalid auth response
                $message = _t(
                    'OpauthLoginForm.RESPONSEVALIDATIONFAILURE',
                    'There was a problem logging in - {message}',
                    [
                        'message' => $e->getMessage(),
                    ]
                );
                break;
        }
        Security::permissionFailure($this, $message);
    }

    /**
     * Looks at $method (GET, POST, PUT etc) for the response.
     * @return array Opauth response
     */
    protected function getResponseFromRequest($method): array
    {
        return unserialize(base64_decode($this->request->{$method . 'Var'}('opauth')));
    }

    /**
     * @param $action
     * @return string
     */
    public function Link($action = null): string
    {
        return Controller::join_links(
            self::config()->opauth_path,
            $action
        );
    }

    /**
     * 'path' param for use in Opauth's config
     * MUST have trailing slash for Opauth needs
     * @return string
     */
    public static function get_path(): string
    {
        return Controller::join_links(
            self::config()->opauth_path,
            'strategy/'
        );
    }

    /**
     * 'callback_url' param for use in Opauth's config
     * MUST have trailing slash for Opauth needs
     * @return string
     */
    public static function get_callback_path(): string
    {
        return Controller::join_links(
            self::config()->opauth_path,
            'finished/'
        );
    }

    /**
     * @return string
     */
    function Title(): string
    {
        if ($this->action == 'profilecompletion') {
            return _t('OpauthController.PROFILECOMPLETIONTITLE', 'Complete your profile');
        }
        return _t('OpauthController.TITLE', 'Social Login');
    }

    /**
     * @return OpauthRegisterForm
     */
    public function Form(): OpauthRegisterForm
    {
        return $this->RegisterForm();
    }

}
