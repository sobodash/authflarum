# AuthFlarum

Have MediaWiki authenticate against a Flarum database for user logins.
This requires Wiki users to have accounts on the Flarum forum.

We can strip out a lot of things central to other user account plugins
because Flarum takes a bare bones approach to user management.

# Installation

Move AuthFlarum.php and iAuthPlugin.php into a "AuthFlarum" folder in your MediaWiki's extension folder.

# Configuration

Add the following to your LocalSettings.php

```
#FlarumAuth plugin (uses old AuthPlugin system)
require_once "$IP/includes/AuthPlugin.php"; //Workaround
require_once "$IP/extensions/AuthFlarum/iAuthPlugin.php"; //Workaround
require_once( "$IP/extensions/AuthFlarum/AuthFlarum.php" );
$wgAuth = new AuthFlarum(
$aConfig = array( 
	"sqlHost" => "databaselocation",
	"sqlDatabase" => "databasename",
	"sqlUsername" => "databaseuser",
	"sqlPassword" => "secretpassword",
	"tblTokens" => "auth_tokens",
	"tblGroups" => "groups",
	"tblUsers" => "users",
	"tblUsersGroups" => "users_groups",
	"msgLogin" => "An account on the Flarum forum is required to log into the wiki.",
	"msgNoPerm" => "You need to be member of the Mods group to log in and edit the wiki.",
	"useWikiGroup" => true,
	"wikiGroupName" => "Mod",
	)
);
$wgGroupPermissions['*']['autocreateaccount'] = true;
```
If you specified a table prefix in your Flarum database don't forget to add it and modify the wikiGroupName to one that actually exist in your Forum (use the singular form of the group name!). It is also possible to set the "useWikiGroup" to false to allow all users of the Flarum to edit the wiki.

If you set the autocreateaccount parameter to false, then only preexisting accounts in your MediaWiki will allow login.

# Other settings

If you want strictly enforce only logins from Flarum and disallow existing 
MediaWiki accounts you can change line 552 in AuthFlarum.php 
(under "public function strict()") to "return true;".
This is not recommended unless you have an already configured admin user ;)

# Known limitations

* It only checks for the specified group but doesn't seem to actually transfer groups from Flarum to MediaWiki
* Due to using the old AuthPlugin.php method the above error messages seem broken in MediaWiki 1.30
* This plugin probably needs a rewrite at some point as it still uses the depreciated AuthPlugin.php methode
* The code in the plugin to pull the email adresses doesn't seem to work

