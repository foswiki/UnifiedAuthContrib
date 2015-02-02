package Foswiki::UnifiedAuth::Providers::Google;

use Error;
use JSON;
use LWP::UserAgent;
use Net::OAuth2::Profile::WebServer;

use strict;
use warnings;

use Foswiki::Plugins::UnifiedAuthPlugin;
use Foswiki::UnifiedAuth;
use Foswiki::UnifiedAuth::Provider;
our @ISA = qw(Foswiki::UnifiedAuth::Provider);

my @schema_updates = (
    [
        "CREATE TABLE providers_google (
            provider_id TEXT NOT NULL,
            email TEXT NOT NULL,
            PRIMARY KEY (provider_id, email)
        )",
        "INSERT INTO meta (type, version) VALUES('providers_google', 0)",
    ]
);

sub new {
    my ($class, $session, $id, $config) = @_;

    my $this = $class->SUPER::new($session, $id, $config);

    return $this;
}

sub useDefaultLogin {
    0;
}

sub _makeOAuth {
    my $this = shift;
    my $ua = LWP::UserAgent->new;
    my $res = $ua->get("https://accounts.google.com/.well-known/openid-configuration");
    die "Error retrieving Google authentication metadata: ".$res->as_string unless $res->is_success;
    my $json = decode_json($res->decoded_content);
    $this->{oid_cfg} = $json;
    Net::OAuth2::Profile::WebServer->new(
        client_id => $this->{config}{client_id},
        client_secret => $this->{config}{client_secret},
        site => '',
        authorize_url => $json->{authorization_endpoint},
        access_token_url => $json->{token_endpoint},
    );
}

sub initiateLogin {
    my ($this, $origin) = @_;

    my $state = $this->SUPER::initiateLogin($origin);

    my $auth = $this->_makeOAuth;
    my $uri = $auth->authorize(
        redirect_uri => $this->processUrl(),
        scope => 'openid email profile',
        state => $state,
        hd => $this->{config}{domain},
    );

    my $session = $this->{session};
    $this->{session}{response}->redirect(
        -url     => $uri,
        -cookies => $session->{response}->cookies(),
        -status  => '302',
    );
    return 1;
}

sub isMyLogin {
    my $this = shift;
    my $req = $this->{session}{request};
    return $req->param('state') && $req->param('code');
}

sub processLogin {
    my $this = shift;
    my $req = $this->{session}{request};
    my $state = $req->param('state');
    $req->delete('state');
    die with Error::Simple("You seem to be using an outdated URL. Please try again.\n") unless $this->SUPER::processLogin($state);

    my $auth = $this->_makeOAuth;
    my $token = $auth->get_access_token($req->param('code'),
        redirect_uri => $this->processUrl(),
    );
    $req->delete('code');
    if ($token->error) {
        die with Error::Simple("Login failed: ". $token->error_description ."\n");
    }
    my $tokenType = $token->token_type;
    $token = $token->access_token;
    my $ua = LWP::UserAgent->new;
    my $acc_info = $ua->simple_request(HTTP::Request->new('GET', $this->{oid_cfg}{userinfo_endpoint},
        ['Authorization', "$tokenType $token"]
    ));
    unless ($acc_info->is_success) {
        die with Error::Simple("Failed to get user information from Google: ". $acc_info->as_string ."\n");
    }
    $acc_info = decode_json($acc_info->decoded_content);

    # email, name, family_name, given_name

    my $uauth = Foswiki::UnifiedAuth->new();
    my $db = $uauth->db;
    $uauth->apply_schema('providers_google', @schema_updates);
    my $exist = $db->selectrow_array("SELECT COUNT(email) FROM providers_google WHERE provider_id=? AND email=?", {}, $this->{id}, $acc_info->{email});
    if ($exist == 0) {
        my $user_id;
        eval {
            $db->begin_work;
            $db->do("INSERT INTO providers_google (provider_id, email) VALUES(?,?)", {}, $this->{id}, $acc_info->{email});
            $user_id = $uauth->add_user('UTF-8', $this->{id}, $acc_info->{email}, $this->_formatWikiName($acc_info), $this->_formatDisplayName($acc_info), $acc_info->{email});
            $db->do("INSERT INTO user_mappings (user_id, mapper_id, mapped_id) VALUES(?,?,?)", {}, $user_id, $this->{id}, $acc_info->{email});
            $db->commit;
        };
        if ($@) {
            my $err = $@;
            eval { $db->rollback; };
            die with Error::Simple("Failed to initialize Google account '$acc_info->{email}' ($err)\n");
        }
        return {
            user_id => $user_id,
            data => $acc_info,
        };
    }

    # Check if values need updating
    my $userdata = $db->selectrow_hashref("SELECT * FROM users NATURAL JOIN user_mappings WHERE mapped_id=?", {}, $acc_info->{email});
    my $cur_dn = $this->_formatDisplayName($acc_info);
    if ($cur_dn ne $userdata->{display_name}) {
        $uauth->update_user('UTF-8', $userdata->{user_id}, $cur_dn, $acc_info->{email})
    }
    return {
        user_id => $userdata->{user_id},
        data => $acc_info,
    }
}

sub _formatWikiName {
    my ($this, $data) = @_;
    my $format = $this->{config}{wikiname_format} || '$name';
    _applyFormat($format, $data);
}
sub _formatDisplayName {
    my ($this, $data) = @_;
    my $format = $this->{config}{displayname_format} || '$name';
    _applyFormat($format, $data);
}
sub _applyFormat {
    my ($format, $data) = @_;
    for my $k (keys %$data) {
        $format =~ s/\$$k\b/$data->{$k}/g;
    }
    return $format;
}

1;
