# See bottom of file for license and copyright information

=begin TML

---+ package Foswiki::Users::UnifiedUserMapping @isa Foswiki::UserMapping');

This is an alternative user mapping that can unify existing user mappings and,
in addition, provide mappings of its own. Similarly, it supports using several
existing group mappings and provides its own.

=cut

package Foswiki::Users::UnifiedUserMapping;
use strict;
use warnings;

use base 'Foswiki::Users::BaseUserMapping';

use Foswiki::UnifiedAuth;

use Assert;
use Error qw( :try );
use Foswiki::ListIterator ();
use Foswiki::Func         ();

=begin TML

---++ ClassMethod new ($session, $impl)

Constructs a new user mapping handler of this type, referring to $session
for any required Foswiki services.

=cut

sub new {
    my ($class, $session) = @_;

    my $this = $class->SUPER::new($session, '');
    $this->{uac} = Foswiki::UnifiedAuth->new();

    return $this;
}



=begin TML

---++ ObjectMethod finish()
Break circular references.

=cut

# Note to developers; please undef *all* fields in the object explicitly,
# whether they are references or not. That way this method is "golden
# documentation" of the live fields in the object.
sub finish {
    my $this = shift;

    $this->{passwords}->finish() if $this->{passwords};
    $this->SUPER::finish();
    Foswiki::UnifiedAuth::finish();
}

sub supportsRegistration {
    # TODO determine dynamically
    return 0;
}

sub handlesUser {
    return 1;
}

sub login2cUID {
    my ( $this, $login, $dontcheck ) = @_;

    unless ($dontcheck) {
        return unless ( _userReallyExists( $this, $login ) );
    }

    return $login;
}

=begin TML

---++ ObjectMethod getLoginName ($cUID) -> login

Converts an internal cUID to that user's login
(undef on failure)

=cut

sub getLoginName {
    my ( $this, $cUID ) = @_;
    ASSERT($cUID) if DEBUG;

    my $login = $cUID;

    return unless _userReallyExists( $this, $login );

    # Validated
    return Foswiki::Sandbox::untaintUnchecked($login);
}

# check for user being present in the mapping DB
sub _userReallyExists {
    my ( $this, $login ) = @_;

    return $this->{uac}->db->selectrow_array(
        "SELECT COUNT(user_id) FROM users WHERE user_id=?", {},
        $login
    );
}

sub addUser {
    my ( $this, $login, $wikiname, $password, $emails ) = @_;

    # to be implemented later
    return '';
}

sub removeUser {
    my ( $this, $cUID ) = @_;

    # to be implemented later
    return '';
}

sub getWikiName {
    my ( $this, $cUID ) = @_;
    ASSERT($cUID) if DEBUG;

    return $this->{uac}->db->selectrow_array(
        "SELECT wiki_name FROM users WHERE user_id=?", {},
        $cUID
    );
}

=begin TML

---++ ObjectMethod userExists($cUID) -> $boolean

Determine if the user already exists or not. We know a user exists if we have
a mapping entry; otherwise we'll guess and/or ask a password manager, if any.

=cut

sub userExists {
    my ( $this, $cUID ) = @_;
    ASSERT($cUID) if DEBUG;

    # Do this to avoid a password manager lookup
    return 1 if $cUID eq $this->{session}->{user};

    my $loginName = $this->getLoginName($cUID);
    return 0 unless defined($loginName);

    return 1;
}

=begin TML

---++ ObjectMethod eachUser () -> Foswiki::Iterator of cUIDs

See baseclass for documentation

=cut

sub eachUser {
    my ($this) = @_;

    my $list = $this->{uac}->db->selectcol_arrayref(
        "SELECT user_id u FROM users WHERE NOT EXISTS (SELECT NULL FROM user_mappings WHERE user_id=u LIMIT 1)"
    );
    return new Foswiki::ListIterator($list);
}

=begin TML

---++ ObjectMethod findUserByEmail( $email ) -> \@cUIDs
   * =$email= - email address to look up
Return a list of canonical user names for the users that have this email
registered with the password manager or the user mapping manager.

The password manager is asked first for whether it maps emails.
If it doesn't, then the user mapping manager is asked instead.

=cut

sub findUserByEmail {
    my ( $this, $email ) = @_;
    ASSERT($email) if DEBUG;

    return $this->{uac}->db->selectcol_arrayref(
        "SELECT user_id FROM users WHERE email=?", {}, $email
    ) || [];
}

sub getEmails {
    my ( $this, $user, $seen ) = @_;

    $seen ||= {};

    my %emails = ();

    if ( $seen->{$user} ) {

        #print STDERR "preventing infinit recursion in getEmails($user)\n";
    }
    else {
        $seen->{$user} = 1;

        if ( $this->isGroup($user) ) {
            my $it = $this->eachGroupMember($user);
            while ( $it->hasNext() ) {
                foreach ( $this->getEmails( $it->next(), $seen ) ) {
                    $emails{$_} = 1;
                }
            }
        }
        else {
            foreach ( mapper_getEmails( $this->{session}, $user ) ) {
                $emails{$_} = 1;
            }
        }
    }
    return keys %emails;
}


=begin TML

---++ StaticMethod mapper_getEmails($session, $user)

Only used if passwordManager->isManagingEmails= = =false
(The emails are stored in the user topics.

Note: This method is PUBLIC because it is used by the tools/upgrade_emails.pl
script, which needs to kick down to the mapper to retrieve email addresses
from Wiki topics.

=cut

sub mapper_getEmails {
    my ( $session, $user ) = @_;

    my $uac = Foswiki::UnifiedAuth->new();
    my $addr = $uac->db->selectrow_array(
        "SELECT email FROM users WHERE user_id=?", {}, $user
    );
    return () if $addr eq '';
    return split(';', $addr);
}

=begin TML

---++ StaticMethod mapper_setEmails ($session, $user, @emails)

Only used if =passwordManager->isManagingEmails= = =false=.
(emails are stored in user topics

=cut

sub mapper_setEmails {
    my $session = shift;
    my $cUID    = shift;

    my $mails = join( ';', @_ );

    my $uac = Foswiki::UnifiedAuth->new();
    $uac->db->do("UPDATE users SET emails=? WHERE user_id=?", {},
        $mails, $cUID);
}

=begin TML

---++ ObjectMethod findUserByWikiName ($wikiname) -> list of cUIDs associated with that wikiname

See baseclass for documentation

The $skipExistanceCheck parameter
is private to this module, and blocks the standard existence check
to avoid reading .htpasswd when checking group memberships).

=cut

sub findUserByWikiName {
    my ( $this, $wn, $skipExistanceCheck ) = @_;

    return [$wn] if $this->isGroup($wn);
    return $this->{uac}->db->selectrow_arrayref(
        "SELECT user_id FROM users WHERE wiki_name=?", {}, $wn) || [];
}


sub checkPassword {
    # Logins to one of our providers never end up here; this can only be
    # caused by using sudo=sudo and then trying to use an account not handled
    # by BaseUserMapping
    0;
}

sub setPassword {
    throw Error::Simple(
        "The standard password change feature is not supported on this site ".
        "because several different login sources are used here."
    );
}

# required so that sudo=sudo login works
sub passwordError {
    return;
}

# functions copied from TopicUserMapping that need to be rewritten later {{{

# callback for search function to collate results
sub _collateGroups {
    my $ref   = shift;
    my $group = shift;
    return unless $group;
    push( @{ $ref->{list} }, $group );
}

# get a list of groups defined in this Wiki
sub _getListOfGroups {
    my $this  = shift;
    my $reset = shift;

    if ( !$this->{groupsList} || $reset ) {
        my $users = $this->{session}->{users};
        $this->{groupsList} = [];

        #create a MetaCache _before_ we do silly things with the session's users
        $this->{session}->search->metacache();

        # Temporarily set the user to admin, otherwise it cannot see groups
        # where %USERSWEB% is protected from view
        local $this->{session}->{user} = 'BaseUserMapping_333';

        $this->{session}->search->searchWeb(
            _callback => \&_collateGroups,
            _cbdata   => {
                list  => $this->{groupsList},
                users => $users
            },
            web       => $Foswiki::cfg{UsersWebName},
            topic     => "*Group",
            scope     => 'topic',
            search    => '1',
            type      => 'query',
            nosummary => 'on',
            nosearch  => 'on',
            noheader  => 'on',
            nototal   => 'on',
            noempty   => 'on',
            format    => '$topic',
            separator => '',
        );
    }
    return $this->{groupsList};
}

# Get a list of *canonical user ids* from a text string containing a
# list of user *wiki* names, *login* names, and *group ids*.
sub _expandUserList {
    my ( $this, $names, $expand ) = @_;

    $expand = 1 unless ( defined $expand );

    #    print STDERR "_expandUserList called  $names - expand $expand \n";

    $names ||= '';

    # comma delimited list of users or groups
    # i.e.: "%MAINWEB%.UserA, UserB, Main.UserC # something else"
    $names =~ s/(<[^>]*>)//go;    # Remove HTML tags

    my @l;
    foreach my $ident ( split( /[\,\s]+/, $names ) ) {

        # Dump the web specifier if userweb
        $ident =~ s/^($Foswiki::cfg{UsersWebName}|%USERSWEB%|%MAINWEB%)\.//;
        next unless $ident;
        if ( $this->isGroup($ident) ) {
            if ( !$expand ) {
                push( @l, $ident );
            }
            else {
                my $it =
                  $this->eachGroupMember( $ident, { expand => $expand } );
                while ( $it->hasNext() ) {
                    push( @l, $it->next() );
                }
            }
        }
        else {

            # Might be a wiki name (wiki names may map to several cUIDs)
            my %namelist =
              map { $_ => 1 }
              @{ $this->{session}->{users}->findUserByWikiName($ident) };

            # If we were not successful in finding by WikiName we assumed it
            # may be a login name (login names map to a single cUID).
            # If user is unknown we return whatever was listed so we can
            # remove deleted or misspelled users
            unless (%namelist) {
                my $cUID = $this->{session}->{users}->getCanonicalUserID($ident)
                  || $ident;
                $namelist{$cUID} = 1 if $cUID;
            }
            push( @l, keys %namelist );
        }
    }
    return \@l;
}

=begin TML

---++ ObjectMethod eachGroupMember ($group) ->  listIterator of cUIDs

See baseclass for documentation

=cut

my %expanding;    # Prevents loops in nested groups

sub eachGroupMember {
    my ( $this, $group, $options ) = @_;

    my $expand = $options->{expand};

    if ( Scalar::Util::tainted($group) ) {
        $group = Foswiki::Sandbox::untaint( $group,
            \&Foswiki::Sandbox::validateTopicName );
    }

    $expand = 1 unless ( defined $expand );

    #    print STDERR "eachGroupMember called for $group - expand $expand \n";

    if ( !$expand && defined( $this->{singleGroupMembers}->{$group} ) ) {

        #        print STDERR "Returning cached unexpanded list for $group\n";
        return new Foswiki::ListIterator(
            $this->{singleGroupMembers}->{$group} );
    }

    if ( $expand && defined( $this->{eachGroupMember}->{$group} ) ) {

        #        print STDERR "Returning cached expanded list for $group\n";
        return new Foswiki::ListIterator( $this->{eachGroupMember}->{$group} );
    }

    #    print "Cache miss for $group expand $expand \n";

    my $session = $this->{session};
    my $users   = $session->{users};

    my $members            = [];
    my $singleGroupMembers = [];

# Determine if we are called recursively, either directly, or by the _expandUserList routine
    unless ( ( caller(1) )[3] eq ( caller(0) )[3]
        || ( caller(2) )[3] eq ( caller(0) )[3] )
    {

        #        print "eachGroupMember $group  - TOP LEVEL \n";
        %expanding = ();
    }

    if (  !$expanding{$group}
        && $session->topicExists( $Foswiki::cfg{UsersWebName}, $group ) )
    {
        $expanding{$group} = 1;

        #        print "Expanding $group \n";
        my $groupTopicObject =
          Foswiki::Meta->load( $this->{session}, $Foswiki::cfg{UsersWebName},
            $group );

        if ( !$expand ) {
            $singleGroupMembers =
              _expandUserList( $this,
                $groupTopicObject->getPreference('GROUP'), 0 );
            $this->{singleGroupMembers}->{$group} = $singleGroupMembers;

#            print "Returning iterator for singleGroupMembers $group, members $singleGroupMembers \n";
            return new Foswiki::ListIterator(
                $this->{singleGroupMembers}->{$group} );
        }
        else {
            $members =
              _expandUserList( $this,
                $groupTopicObject->getPreference('GROUP') );
            $this->{eachGroupMember}->{$group} = $members;
        }

        delete $expanding{$group};
    }

    #    print "Returning iterator for eachGroupMember $group \n";
    return new Foswiki::ListIterator( $this->{eachGroupMember}->{$group} );
}

=begin TML

---++ ObjectMethod isGroup ($user) -> boolean

See baseclass for documentation

=cut

sub isGroup {
    my ( $this, $user ) = @_;

    # Groups have the same username as wikiname as canonical name
    return 1 if $user eq $Foswiki::cfg{SuperAdminGroup};

    return 0 unless ( $user =~ /Group$/ );

   #actually test for the existance of this group
   #TODO: SMELL: this is still a lie, because it will claim that a
   #Group which the currently logged in user does _not_
   #have VIEW permission for simply is non-existant.
   #however, this may be desirable for security reasons.
   #SMELL: this is why we should not use topicExist to test for createability...
    my $iterator = $this->eachGroup();
    while ( $iterator->hasNext() ) {
        my $groupname = $iterator->next();
        return 1 if ( $groupname eq $user );
    }
    return 0;
}

=begin TML

---++ ObjectMethod eachGroup () -> ListIterator of groupnames

See baseclass for documentation

=cut

sub eachGroup {
    my ($this) = @_;
    _getListOfGroups($this);
    return new Foswiki::ListIterator( \@{ $this->{groupsList} } );
}

=begin TML

---++ ObjectMethod eachMembership ($cUID) -> ListIterator of groups this user is in

See baseclass for documentation

=cut

sub eachMembership {
    my ( $this, $user ) = @_;

    _getListOfGroups($this);
    my $it = new Foswiki::ListIterator( \@{ $this->{groupsList} } );
    $it->{filter} = sub {
        $this->isInGroup( $user, $_[0] );
    };
    return $it;
}

=begin TML

---++ ObjectMethod groupAllowsView($group) -> boolean

returns 1 if the group is able to be viewed by the current logged in user

implemented using topic VIEW permissions

=cut

sub groupAllowsView {
    my $this  = shift;
    my $Group = shift;

    my $user = $this->{session}->{user};
    return 1 if $this->{session}->{users}->isAdmin($user);

    $Group = Foswiki::Sandbox::untaint( $Group,
        \&Foswiki::Sandbox::validateTopicName );
    my ( $groupWeb, $groupName ) =
      $this->{session}
      ->normalizeWebTopicName( $Foswiki::cfg{UsersWebName}, $Group );

# If a Group or User topic normalized somewhere else,  doesn't make sense, so ignore the Webname
    $groupWeb = $Foswiki::cfg{UsersWebName};

    $groupName = undef
      if ( not $this->{session}->topicExists( $groupWeb, $groupName ) );

    return Foswiki::Func::checkAccessPermission( 'VIEW', $user, undef,
        $groupName, $groupWeb );
}

=begin TML

---++ ObjectMethod groupAllowsChange($group, $cuid) -> boolean

returns 1 if the group is able to be modified by $cuid

implemented using topic CHANGE permissions

=cut

sub groupAllowsChange {
    my $this  = shift;
    my $Group = shift;
    my $user  = shift;
    ASSERT( defined $user ) if DEBUG;

    $Group = Foswiki::Sandbox::untaint( $Group,
        \&Foswiki::Sandbox::validateTopicName );
    my ( $groupWeb, $groupName ) =
      $this->{session}
      ->normalizeWebTopicName( $Foswiki::cfg{UsersWebName}, $Group );

    # SMELL: Should NobodyGroup be configurable?
    return 0 if $groupName eq 'NobodyGroup';
    return 1 if $this->{session}->{users}->isAdmin($user);

# If a Group or User topic normalized somewhere else,  doesn't make sense, so ignore the Webname
    $groupWeb = $Foswiki::cfg{UsersWebName};

    $groupName = undef
      if ( not $this->{session}->topicExists( $groupWeb, $groupName ) );

    return Foswiki::Func::checkAccessPermission( 'CHANGE', $user, undef,
        $groupName, $groupWeb );
}

=begin TML

---++ ObjectMethod addToGroup( $cuid, $group, $create ) -> $boolean
adds the user specified by the cuid to the group.
If the group does not exist, it will return false and do nothing, unless the create flag is set.

cuid be a groupname which is added like it was an unknown user

=cut

sub addUserToGroup {
    my ( $this, $cuid, $Group, $create ) = @_;
    $Group = Foswiki::Sandbox::untaint( $Group,
        \&Foswiki::Sandbox::validateTopicName );
    my ( $groupWeb, $groupName ) =
      $this->{session}
      ->normalizeWebTopicName( $Foswiki::cfg{UsersWebName}, $Group );

    throw Error::Simple( $this->{session}
          ->i18n->maketext( 'Users cannot be added to [_1]', $Group ) )
      if ( $Group eq 'NobodyGroup' || $Group eq 'BaseGroup' );

    throw Error::Simple(
        $this->{session}->i18n->maketext('Group names must end in Group') )
      unless ( $Group =~ m/Group$/ );

    # the registration code will call this function using the rego agent
    my $user = $this->{session}->{user};

    my $usersObj = $this->{session}->{users};

    print STDERR "$user, aka("
      . $usersObj->getWikiName($user)
      . ") is TRYING to add $cuid aka("
      . $usersObj->getWikiName($cuid)
      . ") to $groupName\n"
      if ( $cuid && DEBUG );

    my $membersString = '';
    my $allowChangeString;
    my $groupTopicObject;

    if ( $usersObj->isGroup($groupName) ) {

        $groupTopicObject =
          Foswiki::Meta->load( $this->{session}, $groupWeb, $groupName );

        if ( !$groupTopicObject->haveAccess( 'CHANGE', $user ) ) {
            throw Error::Simple( $this->{session}
                  ->i18n->maketext( 'CHANGE not permitted by [_1]', $user ) );
        }

        $membersString = $groupTopicObject->getPreference('GROUP') || '';

        my @l;
        foreach my $ident ( split( /[\,\s]+/, $membersString ) ) {
            $ident =~ s/^($Foswiki::cfg{UsersWebName}|%USERSWEB%|%MAINWEB%)\.//;
            push( @l, $ident ) if $ident;
        }
        $membersString = join( ', ', @l );

        if ( $create and !defined($cuid) ) {

            #upgrade group topic.
            $this->_writeGroupTopic(
                $groupTopicObject, $groupWeb, $groupName,
                $membersString,    $allowChangeString
            );

            return 1;
        }
    }
    else {

# see if we have permission to add a topic, or to edit the existing topic, etc..

        throw Error::Simple( $this->{session}
              ->i18n->maketext('Group does not exist and create not permitted')
        ) unless ($create);

        throw Error::Simple(
            $this->{session}->i18n->maketext(
                'CHANGE not permitted for [_1] by [_2]',
                ( $groupName, $user )
            )
          )
          unless (
            Foswiki::Func::checkAccessPermission(
                'CHANGE', $user, '', $groupName, $groupWeb
            )
          );

        $groupTopicObject =
          Foswiki::Meta->load( $this->{session}, $groupWeb, 'GroupTemplate' );

        # expand the GroupTemplate as best we can.
        $this->{session}->{request}
          ->param( -name => 'topic', -value => $groupName );
        $groupTopicObject->expandNewTopic();

        $allowChangeString = $groupName;
    }

    my $wikiName = '';
    $wikiName = $usersObj->getWikiName($cuid) if ($cuid);

    if ( $membersString !~ m/(?:^|\s*,\s*)(?:$wikiName|\Q$cuid\E)(?:$ |\s*,\s*)/x ) {
        $membersString .= ', ' if ( $membersString ne '' );
        $membersString .= $cuid;
    }

    Foswiki::Func::writeEvent( 'addUserToGroup',
        "$groupName: $cuid ($wikiName) added by $user" );

    $this->_clearGroupCache($groupName);

    $this->_writeGroupTopic(
        $groupTopicObject, $groupWeb, $groupName,
        $membersString,    $allowChangeString
    );

    # reparse groups brute force :/
    _getListOfGroups( $this, 1 ) if ($create);
    return 1;
}

#start by just writing the new form.
sub _writeGroupTopic {
    my $this              = shift;
    my $groupTopicObject  = shift;
    my $groupWeb          = shift;
    my $groupName         = shift;
    my $membersString     = shift;
    my $allowChangeString = shift;

    my $text = $groupTopicObject->text() || '';

#TODO: do an attempt to convert existing old style topics - compare to 'normal' GroupTemplate? (I'm hoping to keep any user added descriptions for the group
    if (
        (
            !defined $groupTopicObject->getPreference('VIEW_TEMPLATE')
            or $groupTopicObject->getPreference('VIEW_TEMPLATE') ne 'GroupView'
        )
        or ( $text =~ /^---\+!! <nop>.*$/ )
        or ( $text =~ /^(\t|   )+\* Set GROUP = .*$/ )
        or ( $text =~ /^(\t|   )+\* Member list \(comma-separated list\):$/ )
        or ( $text =~ /^(\t|   )+\* Persons\/group who can change the list:$/ )
        or ( $text =~ /^(\t|   )+\* Set ALLOWTOPICCHANGE = .*$/ )
        or ( $text =~ /^\*%MAKETEXT{"Related topics:"}%.*$/ )
      )
    {
        if ( !defined($allowChangeString) ) {
            $allowChangeString =
              $groupTopicObject->getPreference('ALLOWTOPICCHANGE') || '';
        }

        $text =~ s/^---\+!! <nop>.*$//s;
        $text =~ s/^(\t|   )+\* Set GROUP = .*$//s;
        $text =~ s/^(\t|   )+\* Member list \(comma-separated list\):$//s;
        $text =~ s/^(\t|   )+\* Persons\/group who can change the list:$//s;
        $text =~ s/^(\t|   )+\* Set ALLOWTOPICCHANGE = .*$//s;
        $text =~ s/^\*%MAKETEXT{"Related topics:"}%.*$//s;

        $text .= "\nEdit this topic to add a description to the $groupName\n";

#TODO: consider removing the VIEW_TEMPLATE that only very few people should ever have...
    }

    $groupTopicObject->text($text);

    $groupTopicObject->putKeyed(
        'PREFERENCE',
        {
            type  => 'Set',
            name  => 'GROUP',
            title => 'GROUP',
            value => $membersString
        }
    );
    if ( defined($allowChangeString) ) {
        $groupTopicObject->putKeyed(
            'PREFERENCE',
            {
                type  => 'Set',
                name  => 'ALLOWTOPICCHANGE',
                title => 'ALLOWTOPICCHANGE',
                value => $allowChangeString
            }
        );
    }
    $groupTopicObject->putKeyed(
        'PREFERENCE',
        {
            type  => 'Set',
            name  => 'VIEW_TEMPLATE',
            title => 'VIEW_TEMPLATE',
            value => 'GroupView'
        }
    );

    #TODO: should also consider securing the new topic?
    my $user = $this->{session}->{user};
    $groupTopicObject->saveAs(
        $groupWeb, $groupName,
        author           => $user,
        forcenewrevision => ( $groupName eq $Foswiki::cfg{SuperAdminGroup} )
        ? 1
        : 0
    );

}

=begin TML

---++ ObjectMethod removeFromGroup( $cuid, $group ) -> $boolean

=cut

sub removeUserFromGroup {
    my ( $this, $cuid, $groupName ) = @_;
    $groupName = Foswiki::Sandbox::untaint( $groupName,
        \&Foswiki::Sandbox::validateTopicName );
    my ( $groupWeb, $groupTopic ) =
      $this->{session}
      ->normalizeWebTopicName( $Foswiki::cfg{UsersWebName}, $groupName );

    throw Error::Simple( $this->{session}
          ->i18n->maketext( 'Users cannot be removed from [_1]', $groupName ) )
      if ( $groupName eq 'BaseGroup' );

    throw Error::Simple(
        $this->{session}->i18n->maketext(
            '[_1] cannot be removed from [_2]',
            (
                $Foswiki::cfg{AdminUserWikiName}, $Foswiki::cfg{SuperAdminGroup}
            )
        )
      )
      if ( $groupName eq "$Foswiki::cfg{SuperAdminGroup}"
        && $cuid eq 'BaseUserMapping_333' );

    my $user     = $this->{session}->{user};
    my $usersObj = $this->{session}->{users};

    if (
        $usersObj->isGroup($groupName)
        and ( $this->{session}
            ->topicExists( $Foswiki::cfg{UsersWebName}, $groupName ) )
      )
    {
        if (   !$usersObj->isInGroup( $cuid, $groupName, { expand => 0 } )
            && !$usersObj->isGroup($cuid) )
        {

            throw Error::Simple(
                $this->{session}->i18n->maketext(
                    'User [_1] not in group, cannot be removed', $cuid
                )
            );
        }
        my $groupTopicObject =
          Foswiki::Meta->load( $this->{session}, $Foswiki::cfg{UsersWebName},
            $groupName );
        if ( !$groupTopicObject->haveAccess( 'CHANGE', $user ) ) {

            throw Error::Simple(
                $this->{session}->i18n->maketext(
                    'User [_1] does not have CHANGE permission on [_2].',
                    ( $user, $groupName )
                )
            );
        }

        my $WikiName = $usersObj->getWikiName($cuid);
        my $LoginName = $usersObj->getLoginName($cuid) || '';

        my $membersString = $groupTopicObject->getPreference('GROUP');
        my @l;
        foreach my $ident ( split( /[\,\s]+/, $membersString ) ) {
            $ident =~ s/^($Foswiki::cfg{UsersWebName}|%USERSWEB%|%MAINWEB%)\.//;
            next if ( $ident eq $WikiName );
            next if ( $ident eq $LoginName );
            next if ( $ident eq $cuid );
            push( @l, $ident );
        }
        $membersString = join( ', ', @l );

        Foswiki::Func::writeEvent( 'removeUserFromGroup',
            "$groupTopic: $WikiName removed by $user" );

        $this->_writeGroupTopic( $groupTopicObject, $groupWeb, $groupTopic,
            $membersString );

        $this->_clearGroupCache($groupName);

        return 1;
    }

    return 0;
}

=begin TML

---++ ObjectMethod _clearGroupCache( $groupName )

Removes the cache entries for unexpanded and expanded groups,
and searches un-expanded groups for any nesting group references
clearing them as well.

Note:  This is not recursive and does not attempt to handle
more than one level of nested groups.

=cut

sub _clearGroupCache {
    my ( $this, $groupName ) = @_;

    delete $this->{eachGroupMember}->{$groupName};
    delete $this->{singleGroupMembers}->{$groupName};

    #SMELL:  This should probably be recursive.
    foreach my $groupKey ( keys( %{ $this->{singleGroupMembers} } ) ) {
        if ( $this->{singleGroupMembers}->{$groupKey} =~ m/$groupName/ ) {

            #           print STDERR "Deleting cache for $groupKey \n";
            delete $this->{eachGroupMember}->{$groupKey};
            delete $this->{singleGroupMembers}->{$groupKey};
        }
    }
}

# }}}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2010 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

Additional copyrights apply to some or all of the code in this
file as follows:

Copyright (C) 2007-2008 Sven Dowideit, SvenDowideit@fosiki.com
and TWiki Contributors. All Rights Reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
