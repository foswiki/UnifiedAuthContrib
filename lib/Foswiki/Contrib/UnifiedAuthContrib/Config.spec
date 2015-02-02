# ---+ Extensions
# ---++ UnifiedAuthContrib
# Configure unified authentication here.
# <p>
# This contrib works best when you use <b>UnifiedPasswdUser</b> as the
# password manager, <b>UnifiedLoginManager</b> as the login manager, and
# <b>UnifiedUserMapping</b> as the user mapper.

# ---+++ Defaults

# **SELECTCLASS none,Foswiki::Users::*User EXPERT**
# Password manager to use for logins handled by Foswiki itself, e.g. normal
# TemplateLogin. There is no need to set this when using UnifiedPasswdUser as
# Foswiki's password manager -- which you should if you want to use this
# contrib.
$Foswiki::cfg{UnifiedAuth}{DefaultPasswordManager} = 'none';

# **STRING**
# Choose the auth provider that should be used when authentication is
# required; this should be the ID of an auth provider configured in
# {UnifiedAuth}{Providers} below.
# <p>
# Leave this blank to present a list of options to the user.
$Foswiki::cfg{UnifiedAuth}{DefaultAuthProvider} = '';

# ---+++ ID/name mapping
# UnifiedAuthPlugin assigns a unique ID (cUID) to each user. These IDs are
# used to associate entries in revision histories with users, among other
# things.
# <p>
# By default, a cUID has the format <em>providerid</em>_<em>login</em> (see
# below for information on provider IDs). You can change this default here to
# try and generate shorter cUIDs whenever possible.

# **BOOLEAN**
# Use WikiNames (FirstnameLastname) for cUIDs, instead of login names.
# Multiple identical cUIDs are disambiguated by appending an incrementing
# number (e.g. JohnDoe, JohnDoe1, JohnDoe2, ...)
$Foswiki::cfg{UnifiedAuth}{WikiNameIDs} = 0;

# **BOOLEAN**
# Generate a short cUID, consisting only of the login name. Multiple identical
# short cUIDs are disambiguated by using the default cUID format for all but
# the first (e.g. johndoe, topic_johndoe, oauth_johndoe).
$Foswiki::cfg{UnifiedAuth}{ShortIDs} = 0;

# **BOOLEAN**
# When using short cUIDs, disambiguate by appending a counter instead of using
# the default ID format (e.g. johndoe, johndoe1, johndoe2).
$Foswiki::cfg{UnifiedAuth}{ShortIDIncrement} = 0;

# **STRING**
# UnifiedAuthContrib will automatically normalize arbitrary Unicode strings to
# ASCII if the Text::Unidecode module is installed. That module does not
# perform normalizations that are language-specific, e.g. German umlauts are
# not normalized to "ae", "oe", "ue" etc. because the same characters are used
# by other languages (e.g. Finnish, Turkish) and those normalizations would
# not be appropriate in those language.
# <p>
# You can provide a comma-separated list of language codes here to perform
# special normalization for the corresponding languages. Currently the
# following special normalizations are implemented:
# <strong>
# de
# </strong>
$Foswiki::cfg{UnifiedAuth}{WikiNameNormalizers} = '';

# ---+++ Account merging
# In a future version, UnifiedAuthPlugin will support merging accounts from
# several auth providers into a single wiki user ID.

# ---+++ Authentication providers

# **PERL**
# A hash of authentication providers. The key is the ID you want to use for
# the authentication provider (please use that begins with a letter and
# contains only alphanumerical characters and underscores); the value is a
# hash of configuration options.
# <br>
# An auth provider ID must not be used twice.
# <p>
# <strong>The ID of an authentication provider must not be changed once you
# have added it.</strong> If you do change it, your mappings will break.
# <p>
# The configuration of each auth provider has the following keys:
# <ul>
# <li><code>module</code>: the name of the module implementing this auth
# provider. It can be the class name of a Foswiki password manager or of one
# of the auth provider classes shipped with UnifiedAuthPlugin or any
# companion extensions (minus the
# <code>Foswiki::UnifiedAuth::Providers::</code> suffix).
# <li><code>mapper_module</code>: when using a Foswiki password manager,
# specify the name of the corresponding user mapper here if required (e.g. for
# automatically importing users from LdapContrib).
# <li><code>login_module</code>: when using a Foswiki password manager,
# specify the name of the appropriate login manager here if required (defaults
# to something that is equivalent to TemplateLogin).
# <li><code>config</code>: any configuration passed to the module. For Foswiki
# password managers, the structure in this will be merged with $Foswiki::cfg
# whenever the password manager is called, so you can use it to override the
# password manager's config as set in its own category in this interface. For
# native UnifiedAuth modules, see the documentation included in the contrib
# that includes it.
# <li><code>hidden</code>: set to 1 to exclude this auth provider from the
# list shown to users.
# </ul>
$Foswiki::cfg{UnifiedAuth}{Providers} = {};

1;
