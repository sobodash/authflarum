<?php

/**
 * Have MediaWiki authenticate against a Flarum database for user logins.
 * This requires Wiki users to have accounts on a forum.
 *
 * We can strip out a lot of things central to other user account plugins
 * because Flarum takes a bare bones approach to user management. Users and
 * groups already work pretty much perfectly with MediaWiki.
 *
 * @package MediaWiki
 * @subpackage AuthFlarum
 * @author Derrick Sobodash
 * @copyright 2016 Derick Sobodash
 * @license http://www.gnu.org/copyleft/gpl.html
 * @link https://github.com/Digitalroot/MediaWiki_PHPBB_Auth
 *
 */

// Ensure class and interface are defined.
/** ERROR causes issues with update.php, add to local settings instead
if (!class_exists('AuthPlugin') || !interface_exists('iAuthPlugin'))
{
    require_once './includes/AuthPlugin.php';
    require_once './extensions/AuthFlarum/iAuthPlugin.php';
}
 */

/**
 * Authenticate against a Flarum database.
 */
class AuthFlarum extends AuthPlugin implements iAuthPlugin
{

    /**
     * Database Collation (Only change this if your know what to change it to)
     *
     * @var string
     */
    private $_DB_Collation,    // Database Collation

            $_sqlVersion,      // MySQL version
            $_sqlHost,         // MySQL host
            $_sqlDatabase,     // MySQL database
            $_sqlUsername,     // MySql username
            $_sqlPassword,     // MySQL password

            $_tblTokens,       // Flarum sign-on tokens table
            $_tblGroups,       // Flarum group names table
            $_tblUsers,        // Flarum user table
            $_tblUsersGroups,  // Flarum group membership table

            $_msgLogin,        // Login message
            $_msgNoPerm,       // Error message for no permissions

            $_userID,          // ID of current user

            $_useWikiGroup,    // Require user to be in Wiki group
            $_wikiGroupName;   // Name of group with Wiki permission


    /**
     * Constructor
     *
     * @param array $aConfig
     */
    function __construct($aConfig)
    {
        // Read read config and supress any non-essential errors
        $this->_sqlHost         =  $aConfig['sqlHost'];
        $this->_sqlDatabase     =  $aConfig['sqlDatabase'];
        $this->_sqlUsername     =  $aConfig['sqlUsername'];
        $this->_sqlPassword     =  $aConfig['sqlPassword'];

        $this->_tblTokens       = @$aConfig['tblTokens'];
        $this->_tblGroups       = @$aConfig['tblGroups'];
        $this->_tblUsers        = @$aConfig['tblUsers'];
        $this->_tblUsersGroups  = @$aConfig['tblUsersGroups'];

        $this->_msgLogin        = @$aConfig['msgLogin'];
        $this->_msgNoPerm       = @$aConfig['msgNoPerm'];

        $this->_useWikiGroup    = @$aConfig['useWikiGroup'];
        $this->_wikiGroupName   = @$aConfig['wikiGroupName'];

        // Set sane defaults for things the user may have skipped
        if(!isset($this->_tblTokens))      $this->_tblTokens = "auth_tokens";
        if(!isset($this->_tblGroups))      $this->_tblGroups = "groups";
        if(!isset($this->_tblUsers))       $this->_tblUsers = "users";
        if(!isset($this->_tblUsersGroups)) $this->_tblUsersGroups = "users_groups";
        if(!isset($this->_useWikiGroup))   $this->_useWikiGroup = false;

        if(!isset($this->_msgLogin))
            $this->_msgLogin = "An account on this site's discussion forum is required to edit the wiki.";
        if(!isset($this->_msgNoPerm))
            $this->_msgLogin = "Your account does not have permission to log in and edit the wiki.";

        // Disable anonymous editing
        $GLOBALS['wgGroupPermissions']['*']['edit'] = false;

        // Prevent all classes from creating Wiki accounts
        $GLOBALS['wgGroupPermissions']['*']['createaccount'] = false;

        // Load Hooks
        $GLOBALS['wgHooks']['UserLoginForm'][]     = array($this, 'onUserLoginForm', false);
        $GLOBALS['wgHooks']['UserLoginComplete'][] = $this;
        $GLOBALS['wgHooks']['UserLogout'][]        = $this;
    }


    /**
     * Connect to the database and return a handle to the connection.
     *
     * {@source }
     * @return resource
     */
    private function connect()
    {
        // Open connection to the database
        $sqlConnection = new mysqli($this->_sqlHost, $this->_sqlUsername, $this->_sqlPassword, $this->_sqlDatabase);

        // Check if successful
        if ($sqlConnection->connect_errno > 0)
            $this->mySQLError(
                'There was a problem when connecting to the Flarum database.<br />' .
                'Check the host, username and password settings in your MediaWiki config.<br />');

        // Store MySQL version
        $this->_sqlVersion = substr($sqlConnection->server_info, 0, 3);

        return $sqlConnection;
    }


    /**
     * Check if the supplied username and password exist in Flarum.
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @access public
     */
    public function authenticate($username, $password)
    {
        // Connect to the database
        $sqlConnection = $this->connect();

        $username = $sqlConnection->escape_string($username);

        // Check database for username and password
        $sqlQuery = sprintf(
               "SELECT `id`, `username`, `password`
                FROM `%s`
                WHERE `username` = ? AND `is_activated` = 1
                LIMIT 1", $this->_tblUsers);

        // Query the database
        $sqlStatement = $sqlConnection->prepare($sqlQuery);
        $sqlStatement->bind_param('s', $username);
        $sqlStatement->execute();

        // Bind results
        $sqlStatement->bind_result($resultID, $resultUsername, $resultPassword);

        while($sqlStatement->fetch())
        {
            // Test password
            if(password_verify($password, $resultPassword) && $this->isMemberOfWikiGroup($username))
            {
                $this->_userID = $resultID;
                return true;
            }
        }

        return false;
    }


    /**
     * If you want to munge the case of an account name before the final
     * check, now is your chance.
     *
     * @return string
     */
    public function getCanonicalName($username)
    {
        // Connect to the database.
        $sqlConnection = $this->connect();

        $username = $sqlConnection->escape_string($username);

        // Check Database for username. We will return the correct casing of the name.
        $sqlQuery = sprintf(
               "SELECT `username`
                FROM `%s`
                WHERE `username` = ?
                LIMIT 1", $this->_tblUsers);

        // Query Database.
        $sqlStatement = $sqlConnection->prepare($sqlQuery);
        $sqlStatement->bind_param('s', $username);
        $sqlStatement->execute();

        // Bind result
        $sqlStatement->bind_result($resultUsername);

        while($sqlStatement->fetch())
            return ucfirst($resultUsername);

        // At this point the username is invalid and should return just as it was passed.
        return $username;
    }


    /**
     * When creating a user account, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * NOTE: This gets the email address from PHPBB for the wiki account.
     *
     * @param User $user
     * @param $autocreate bool True if user is being autocreated on login
     * @access public
     */
    public function initUser(&$user, $autocreate=false)
    {
        // Connect to the database.
        $sqlConnection = $this->connect();

        $username = $sqlConnection->escape_string($username);

        // Check Database for username and email address.
        $sqlQuery = sprintf(
               "SELECT `username`, `email`
                FROM `%s`
                WHERE `username` = ?
                LIMIT 1", $this->_tblUsers);

        // Query Database.
        $sqlStatement = $sqlConnection->prepare($sqlQuery);
        $sqlStatement->bind_param('s', $username);
        $sqlStatement->execute();

        // Bind result
        $sqlStatement->bind_result($resultUsername, $resultEmail);

        while($sqlStatement->fetch())
        {
            $user->mEmail       = $resultEmail; // Set Email Address.
            $user->mRealName    = $resultUsername;  // Set Real Name.
        }
    }


    private function hasCredential($username, $credential)
    {
        $conn = $this->getConnection();

        $username   = $sqlConnection->escape_string($username);
        $credential = $sqlConnection->escape_string($credential);

        // Check database for username and email address.
        $sqlQuery = sprintf('SELECT `username`, `name_singular`
                            FROM `%s` AS u
                            LEFT JOIN `%s` up ON u.id = up.user_id
                            LEFT JOIN `%s` p ON up.group_id = p.id
                            WHERE u.username = "%s" AND p.name_singular = "%s"
                            LIMIT 1',
                            $this->_tblUsers, $this->_tblUsersGroups, $this->_tblGroups, $username, $credential);

        // Query Database.
        $sqlStatement = $sqlConnection->prepare($sqlQuery);
        $sqlStatement->bind_param('s', $username);
        $sqlStatement->bind_param('s', $credential);
        $sqlStatement->execute();

        // Bind result
        $sqlStatement->bind_result($resultUsername, $resultGroup);

        while($sqlStatement->fetch())
        {
            $user->mEmail       = $resultEmail; // Set Email Address.
            $user->mRealName    = $resultUsername;  // Set Real Name.
        }

    }

    /**
     * Checks if the user is a member of the PHPBB group called wiki.
     *
     * @param string $username
     * @access public
     * @return bool
     * @todo Remove 2nd connection to database. For function isMemberOfWikiGroup()
     *
     */
    private function isMemberOfWikiGroup($username)
    {
        // In LocalSettings.php you can control if being a member of a wiki
        // is required or not.
        if(isset($this->_useWikiGroup) && $this->_useWikiGroup === false)
            return true;

        // Connect to the database.
        $sqlConnection = $this->connect();

        $username = $sqlConnection->escape_string($username);

        // If not an array make this an array.
        if(!is_array($this->_wikiGroupName))
            $this->_wikiGroupName = array($this->_wikiGroupName);

        foreach($this->_wikiGroupName as $wikiGroup)
        {
            /**
             *  This is a great query. It takes the username and gets the userid. Then
             *  it gets the group_id number of the the Wiki group. Last it checks if the
             *  userid and groupid are matched up. (The user is in the wiki group.)
             *
             *  Last it returns TRUE or FALSE on if the user is in the wiki group.
             */

            // Get UserId
            $sqlQuery = sprintf(
                   "SELECT `id` FROM `%s`
                    WHERE `username` = ?", $this->_tblUsers);

            $sqlStatement = $sqlConnection->prepare($sqlQuery);
            $sqlStatement->bind_param('s', $username);
            $sqlStatement->execute();
            $sqlStatement->bind_result($resultID);
            $user_id = -1;
            while ($sqlStatement->fetch())
                $user_id = $resultID;

            // Get WikiId
            $sqlQuery = sprintf(
                   'SELECT `id` FROM `%s`
                    WHERE `name_singular` = \'%s\'', $this->_tblGroups, $wikiGroup);

            $sqlStatement = $sqlConnection->prepare($sqlQuery);
            $sqlStatement->execute();
            $sqlStatement->bind_result($resultGroupID);

            $group_id = -1;
            while ($sqlStatement->fetch())
                $group_id = $resultGroupID;

            // Check UserId and WikiId
            $sqlQuery = sprintf(
                   "SELECT COUNT( * ) FROM `%s`
                    WHERE `user_id` = ? AND `group_id` = ?", $this->_tblUsersGroups);

            $sqlStatement = $sqlConnection->prepare($sqlQuery);
            $sqlStatement->bind_param('ii', $user_id, $group_id);
            $sqlStatement->execute();

            // Bind result
            $sqlStatement->bind_result($result);

            // Check for a true or false response.
            while($sqlStatement->fetch())
                if($result == '1')
                    return true; // User is in Wiki group.
        }

        // Hook error message.
        $GLOBALS['wgHooks']['UserLoginForm'][] = array($this, 'onUserLoginForm', $this->_msgNoPerm);
        return false; // User is not in Wiki group.
    }


    /**
     * Modify options in the login template.
     *
     * NOTE: Turned off some Template stuff here. Anyone who knows where
     * to find all the template options please let me know. I was only able
     * to find a few.
     *
     * @param UserLoginTemplate $template
     * @access public
     */
    public function modifyUITemplate(&$template, &$type)
    {
        $template->set('usedomain', false); // We do not want a domain name.
        $template->set('create',    false); // Remove option to create new accounts from the wiki.
        $template->set('useemail',  false); // Disable the mail new password box.
    }


    /**
     * This prints an error when a MySQL error is found.
     *
     * @param string $message
     * @access public
     */
    private function mySQLError($message)
    {
        throw new Exception('MySQL error: ' . $message . '<br /><br />');
    }


    /**
     * This is the hook that runs when a user logs in. This is where the
     * code to auto log-in a user to phpBB should go.
     *
     * Note: Right now it does nothing,
     *
     * @param object $user
     * @return bool
     */
    public function onUserLoginComplete(&$user)
    {
        // @ToDo: Add code here to auto log into the forum.
        return true;
    }


    /**
     * Here we add some text to the login screen telling the user
     * they need a phpBB account to login to the wiki.
     *
     * Note: This is a hook.
     *
     * @param string $errorMessage
     * @param object $template
     * @return bool
     */
    public function onUserLoginForm($errorMessage = false, $template)
    {
        $template->data['link'] = $this->_msgLogin;

        // If there is an error message display it.
        if ($errorMessage)
        {
            $template->data['message'] = $errorMessage;
            $template->data['messagetype'] = 'error';
        }

        return true;
    }


    /**
     * This is the Hook that gets called when a user logs out.
     *
     * @param object $user
     */
    public function onUserLogout(&$user)
    {
        // User logs out of the wiki we want to log them out of the form too.
        if (!isset($this->_tblTokens))
            return true; // If the value is not set just return true and move on.

        return true;
        // @todo: Add code here to delete the session.
    }


    /**
     * Set the domain this plugin is supposed to use when authenticating.
     *
     * NOTE: We do not use this.
     *
     * @param string $domain
     * @access public
     */
    public function setDomain($domain)
    {
        $this->domain = $domain;
    }


    /**
     * Check whether there exists a user account with the given name.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * NOTE: MediaWiki checks its database for the username. If it has
     *       no record of the username it then asks. "Is this really a
     *       valid username?" If not then MediaWiki fails Authentication.
     *
     * @param string $username
     * @return bool
     * @access public
     */
    public function userExists($username)
    {

        // Connect to the database.
        $sqlConnection = $this->connect();

        $username = $sqlConnection->escape_string($username);

        // Check Database for username.
        $sqlQuery = sprintf(
               "SELECT `username`
                FROM `%s`
                WHERE `username` = ?
                LIMIT 1", $this->_tblUsers);

        // Query Database.
        $sqlStatement = $sqlConnection->prepare($sqlQuery);
        $sqlStatement->bind_param('s', $username);
        $sqlStatement->execute();

        // Bind result
        $sqlStatement->bind_result($resultUsername);

        // Double check match.
        while($sqlStatement->fetch())
            if ($username == $resultUsername)
                return true; // Pass

        return false; // Fail
    }


    // Users are only aded through Flarum
    public function addUser($user, $password, $email='', $realname='')
    {
        return false;
    }
    public function autoCreate()
    {
        return true;
    }
    public function canCreateAccounts()
    {
        return false;
    }


    // Simple enough to implement Wiki-side so why not?
    public function allowPasswordChange()
    {
        return true;
    }
    public function setPassword($user, $password)
    {
        return true;
    }


    // Don't authenticate off any other tables
    public function strict()
    {
        return false;
    }


    // No need to check domains
    public function validDomain($domain)
    {
        return true;
    }


    // Lie about updating user information
    public function updateExternalDB($user)
    {
        return true;
    }


    // Lie about updating the user's info
    public function updateUser(&$user)
    {
        return true;
    }

}
