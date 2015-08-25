# See bottom of file for license and copyright information

=begin TML

---+ package Foswiki::LoginManager::UnifiedLogin

=cut

package Foswiki::LoginManager::UnifiedLogin;

use strict;
use warnings;
use Assert;

use JSON;

use Foswiki::LoginManager ();
our @ISA = ('Foswiki::LoginManager');

sub new {
    my ( $class, $session ) = @_;
    my $this = $class->SUPER::new($session);
    $session->enterContext('can_login');
    if ( $Foswiki::cfg{Sessions}{ExpireCookiesAfter} ) {
        $session->enterContext('can_remember_login');
    }
    return $this;
}

# Pack key request parameters into a single value
# Used for passing meta-information about the request
# through a URL (without requiring passthrough)
# Copied from TemplateLogin
sub _packRequest {
    my ( $uri, $method, $action ) = @_;
    return '' unless $uri;
    if ( ref($uri) ) {    # first parameter is a $session
        my $r = $uri->{request};
        $uri    = $r->uri();
        $method = $r->method() || 'UNDEFINED';
        $action = $r->action();
    }
    return "$method,$action,$uri";
}

# Unpack single value to key request parameters
# Copied from TemplateLogin
sub _unpackRequest {
    my $packed = shift || '';
    my ( $method, $action, $uri ) = split( ',', $packed, 3 );
    return ( $uri, $method, $action );
}

sub _authProvider {
    my ($this, $id) = @_;
    my $cfg = $Foswiki::cfg{UnifiedAuth}{Providers}{$id};

    if ($cfg->{module} =~ /^Foswiki::Users::/) {
        die("Auth providers based on Foswiki password managers are not supported yet");
        #return Foswiki::UnifiedAuth::Providers::Passthrough->new($this->{session}, $id, $cfg);
    }

    my $package = "Foswiki::UnifiedAuth::Providers::$cfg->{module}";
    eval "require $package"; ## no critic (ProhibitStringyEval);
    if ($@ ne '') {
        die "Failed loading auth provider: $@";
    }
    my $authProvider = $package->new($this->{session}, $id, $cfg->{config});
}

sub forceAuthentication {
    my $this    = shift;
    my $session = $this->{session};

    unless ( $session->inContext('authenticated') ) {
        my $query    = $session->{request};
        my $response = $session->{response};

        my $authid = $Foswiki::cfg{UnifiedAuth}{DefaultAuthProvider};
        if ($authid ne '') {
            my $auth = $this->_authProvider($authid);
            return $auth->initiateLogin(_packRequest($session)) unless $auth->useDefaultLogin;
        }

        # Respond with a 401 with an appropriate WWW-Authenticate
        # that won't be snatched by the browser, but can be used
        # by JS to generate login info.
        $response->header(
            -status           => 401,
            -WWW_Authenticate => 'FoswikiBasic realm="'
              . ( $Foswiki::cfg{AuthRealm} || "" ) . '"'
        );

        $query->param(
            -name  => 'foswiki_origin',
            -value => _packRequest($session)
        );

        # Throw back the login page with the 401
        $this->login( $query, $session );
    }
    return 0;
}

sub loginUrl {
    my $this    = shift;
    my $session = $this->{session};
    my $topic   = $session->{topicName};
    my $web     = $session->{webName};
    return $session->getScriptUrl( 0, 'login', $web, $topic,
        foswiki_origin => _packRequest($session) );
}

sub _loadTemplate {
    my $this = shift;
    my $tmpls = $this->{session}->templates;
    $this->{tmpls} = $tmpls;
    return $tmpls->readTemplate('uauth');
}

sub _renderTemplate {
    my ($this, $tmpl, %params) = @_;
    my $session = $this->{session};
    $session->{prefs}->setSessionPreferences(%params);
    my $topicObject = Foswiki::Meta->new($session, $session->{webName}, $session->{topicName});
    $tmpl = $topicObject->expandMacros($tmpl);
    $tmpl = $topicObject->renderTML($tmpl);
    $tmpl =~ s/<nop>//g;
    $session->writeCompletePage($tmpl);
}

=begin TML

---++ ObjectMethod login( $query, $session )

If a login name and password have been passed in the query, it
validates these and if authentic, redirects to the original
script. If there is no username in the query or the username/password is
invalid (validate returns non-zero) then it prompts again.

If a flag to remember the login has been passed in the query, then the
corresponding session variable will be set. This will result in the
login cookie being preserved across browser sessions.

The password handler is expected to return a perl true value if the password
is valid. This return value is stored in a session variable called
VALIDATION. This is so that password handlers can return extra information
about the user, such as a list of Wiki groups stored in a separate
database, that can then be displayed by referring to
%<nop>SESSION_VARIABLE{"VALIDATION"}%

=cut

sub login {
    my ( $this, $query, $session ) = @_;
    my $users = $session->{users};

    my $cgis = $session->getCGISession();
    my $provider;
    $provider = $cgis->param('uauth_provider') if $cgis;

    my $topic  = $session->{topicName};
    my $web    = $session->{webName};

    my $context = Foswiki::Func::getContext();
    unless ($Foswiki::cfg{UnifiedAuth}{DefaultAuthProvider}) {
        $context->{uauth_choose} = 1;
    }

    $session->{request}->delete('validation_key');
    if ($provider) {
        $provider = $this->_authProvider($provider);
        if ($provider->isMyLogin) {
            my $loginResult;
            my $error = '';
            eval {
                $loginResult = $provider->processLogin();
            };
            if ($@) {
                $error = $@;
                $error = $@->text if ref($@) && $@->isa("Error");
            }
            if (ref($loginResult) eq 'HASH' && $loginResult->{user_id}) {
                $this->userLoggedIn($loginResult->{user_id});

                $session->logger->log(
                    {
                        level    => 'info',
                        action   => 'login',
                        webTopic => $web . '.' . $topic,
                        extra    => "AUTHENTICATION SUCCESS - $loginResult->{user_id} - "
                    }
                );
                $this->{_cgisession}->param( 'VALIDATION', encode_json($loginResult->{data} || {}) )
                  if $this->{_cgisession};
                my ( $origurl, $origmethod, $origaction ) = _unpackRequest($provider->origin);
                my $current_uri = $query->uri;
                $current_uri =~ s/\?.*$//;
                my ($origurl_noquery) = ($origurl =~ /^(.*?)(?:\?.*)?$/);
                if (!$origurl || $origurl_noquery eq $current_uri) {
                    $origurl = $session->getScriptUrl(0, 'view', $web, $topic);
                    $session->{request}->delete_all;
                } else {
                    # Unpack params encoded in the origurl and restore them
                    # to the query. If they were left in the query string they
                    # would be lost if we redirect with passthrough.
                    # First extract the params, ignoring any trailing fragment.
                    if ( $origurl =~ s/\?([^#]*)// ) {
                        foreach my $pair ( split( /[&;]/, $1 ) ) {
                            if ( $pair =~ /(.*?)=(.*)/ ) {
                                $session->{request}->param( $1, TAINT($2) );
                            }
                        }
                    }

                    # Restore the action too
                    $session->{request}->action($origaction) if $origaction;
                }
                $session->{request}->method($origmethod);
                $session->redirect($origurl, 1);
                return;
            }

            if ($Foswiki::cfg{UnifiedAuth}{DefaultAuthProvider}) {
                $context->{uauth_failed_nochoose} = 1;
            }
            $session->{response}->status(200);
            $session->logger->log(
                {
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION FAILURE",
                }
            );
            my $tmpl = $this->_loadTemplate;
            my $banner = $this->{tmpls}->expandTemplate('AUTH_FAILURE');
            return $this->_renderTemplate($tmpl,
                UAUTH_AUTH_FAILURE_MESSAGE => $error,
                BANNER => $banner,
            );
        }
    }

    if (my $forceauthid = $session->{request}->param('uauth_force_provider')) {
        if (!exists $Foswiki::cfg{UnifiedAuth}{Providers}{$forceauthid}) {
            die "Invalid authentication source requested";
        }
        my $auth = $this->_authProvider($forceauthid);
        return $auth->initiateLogin(_packRequest($session));
    }

    if (my $authid = $Foswiki::cfg{UnifiedAuth}{DefaultAuthProvider}) {
        my $auth = $this->_authProvider($authid);
        return $auth->initiateLogin(_packRequest($session));
    }

    die("Login selection page not supported yet");
}

1;
__END__
Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2014 Foswiki Contributors. All Rights Reserved.
Foswiki Contributors are listed in the AUTHORS file in the root
of this distribution. NOTE: Please extend that file, not this notice.

Additional copyrights apply to some or all of the code in this
file as follows:

Copyright (C) 2005-2006 TWiki Contributors. All Rights Reserved.
Copyright (C) 2005 Greg Abbas, twiki@abbas.org

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

