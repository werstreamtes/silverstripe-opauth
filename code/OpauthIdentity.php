<?php

namespace WSE\Opauth;

use InvalidArgumentException;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\ArrayLib;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * OpauthIdentity
 * The SS equivalent of "index.php" and "callback.php" in the Opauth package.
 * @author Will Morgan <@willmorgan>
 * @author Dan Hensby <@dhensby>
 * @copyright Copyright (c) 2013, Better Brief LLP
 */
class OpauthIdentity extends DataObject
{

    private static
        $db = [
        'UID' => 'Varchar(255)',
        'Provider' => 'Varchar(45)',
    ],
        $has_one = [
        'Member' => 'Member',
    ],
        $summary_fields = [
        'Member.Email' => 'MemberEmail',
        'Provider' => 'Provider',
        'UID' => 'UID',
    ];

    protected
        /**
         * @var array source from Opauth
         */
        $authSource,
        /**
         * @var array The parsed member record, if any
         */
        $parsedRecord;

    private
        /**
         * @var boolean shim for onBeforeCreate
         */
        $_isCreating = false;

    /**
     * factory
     * Returns or creates a fresh OpauthIdentity.
     * @param array $oaResponse The response object from Opauth.
     * @return OpauthIdentity instance based on $oaResponse.
     */
    public static function factory(array $oaResponse): OpauthIdentity
    {

        if (empty($oaResponse['auth'])) {
            throw new InvalidArgumentException('The auth key is required to continue.');
        }
        if (empty($oaResponse['auth']['provider'])) {
            throw new InvalidArgumentException('Unable to determine provider.');
        }

        $auth = $oaResponse['auth'];

        $do = OpauthIdentity::get()->filter(
            [
                'Provider' => $auth['provider'],
                'UID' => $auth['uid'],
            ]
        )->first();

        if (!$do || !$do->exists()) {
            $do = new OpauthIdentity();
            $do->Provider = $auth['provider'];
            $do->UID = $auth['uid'];
        }

        $do->setAuthSource($auth);
        return $do;
    }

    /**
     * Add an extension point for creation and member linking
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if (!$this->isInDb()) {
            $this->_isCreating = true;
            $this->extend('onBeforeCreate');
        }
        if ($this->isChanged('MemberID')) {
            $this->extend('onMemberLinked');
        }
    }

    /**
     * Add an extension point for afterCreate
     */
    public function onAfterWrite()
    {
        parent::onAfterWrite();
        if ($this->_isCreating === true) {
            $this->_isCreating = false;
            $this->extend('onAfterCreate');
        }
    }

    /**
     * Finds a member based on this identity. Searches existing records before
     * creating a new Member object.
     * Note that this method does not write anything, merely sets everything up.
     * @param array $usrSettings A map of settings because there are so many.
     * @return Member
     */
    public function findOrCreateMember(array $usrSettings = []): Member
    {

        $defaults = [
            /**
             * Link this identity to any newly discovered member.
             */
            'linkOnMatch' => true,
            /**
             * True, false, or an array of fields to overwrite if we merge data.
             * Exception to this rule is overwriteEmail, which takes precedence.
             */
            'overwriteExistingFields' => false,
            /**
             * Overwrite the email field if it's different. Effectively changes
             * the Member login details, so it's set to false for now.
             */
            'overwriteEmail' => false,
        ];

        $settings = array_merge($defaults, $usrSettings);

        if ($this->isInDB()) {
            $member = $this->Member();
            if ($member->exists()) {
                return $member;
            }
        }

        $record = $this->getMemberRecordFromAuth();

        if (empty($record['Email'])) {
            $member = new Member();
        } else {
            $member = Member::get()->filter('Email', $record['Email'])->first();

            if (!$member) {
                $member = new Member();
            }
        }

        if ($settings['linkOnMatch'] && $member->isInDB()) {
            $this->MemberID = $member->ID;
        }

        // If this is a new member, give it everything we have.
        if (!$member->isInDB()) {
            $member->update($record);
        } // If not, we update it carefully using the settings described above.
        else {
            $overwrite = $settings['overwriteExistingFields'];
            $overwriteEmail = $settings['overwriteEmail'];
            $fieldsToWrite = [];

            // If overwrite is true, take everything (subtract Email later)
            if ($overwrite === true) {
                $fieldsToWrite = $record;
            } else if (is_array($overwrite)) {
                $fieldsToWrite = array_intersect_key($record, ArrayLib::valuekey($overwrite));
            }
            // If false then fieldsToWrite remains empty, let's coast it out.

            // Subtract email if setting is not precisely true:
            if ($overwriteEmail !== true && isset($fieldsToWrite['Email'])) {
                unset($fieldsToWrite['Email']);
            }

            // Boom, we're so done.
            $member->update($fieldsToWrite);
        }

        return $member;
    }

    /**
     * @param array $auth
     */
    public function setAuthSource($auth): OpauthIdentity
    {
        $this->authSource = $auth;
        unset($this->parsedRecord);
        return $this;
    }

    /**
     * @return array
     */
    public function getAuthSource(): array
    {
        return $this->authSource;
    }

    /**
     * @return array The mapping arrangement from auth response to Member.
     */
    public function getMemberMapper(): array
    {
        $mapper = Config::inst()->get(__CLASS__, 'member_mapper');
        if (!isset($mapper[$this->Provider])) {
            return [];
        }
        return $mapper[$this->Provider];
    }

    /**
     * Use dot notation and/or a parser to retrieve information from a provider.
     * Examples of simple dot notation:
     * - 'FirstName' => 'info.first_name'
     * - 'Surname' => 'info.surname'
     * Examples of a parser, for example when only a "name" param is present:
     * - 'FirstName' => array('OpauthResponseHelper', 'get_first_name')
     * - 'Surname' => array('OpauthResponseHelper', 'get_last_name')
     * @return array The data record to add to a member
     * @see OpauthResponseHelper
     */
    public function getMemberRecordFromAuth(): array
    {
        if (empty($this->parsedRecord)) {
            $record = [];
            foreach ($this->getMemberMapper() as $memberField => $sourcePath) {
                if (is_array($sourcePath)) {
                    $record[$memberField] = call_user_func($sourcePath, $this->authSource);
                } else if (is_string($sourcePath)) {
                    $record[$memberField] = OpauthResponseHelper::parse_source_path($sourcePath, $this->authSource);
                }
            }
            $this->parsedRecord = $record;
        }
        return $this->parsedRecord;
    }

}
