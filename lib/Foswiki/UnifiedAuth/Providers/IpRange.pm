package Foswiki::UnifiedAuth::Providers::IpRange;

use Error;
use JSON;
use Net::CIDR;

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

sub initiateLogin {
    my ($this, $origin) = @_;

    my $state = $this->SUPER::initiateLogin($origin);

    my $session = $this->{session};
    $session->{response}->redirect(
        -url     => $this->processUrl() .'?state='. Foswiki::urlEncode($state),
        -cookies => $session->{response}->cookies(),
        -status  => '302',
    );
    return 1;
}

sub isMyLogin {
    my $this = shift;
    my $req = $this->{session}{request};
    return $req->param('state');
}

sub processLogin {
    my $this = shift;
    my $req = $this->{session}{request};
    my $id = $this->{id};
    my $config = $this->{config};
    my $state = $req->param('state');
    $req->delete('state');
    die with Error::Simple("You seem to be using an outdated URL. Please try again.\n") unless $this->SUPER::processLogin($state);

    my $iprange = $config->{ip_range};
    my @iprange = ref($iprange) ? @$iprange : $iprange;
    @iprange = () if @iprange && !defined $iprange[0];
    if (!Net::CIDR::cidrlookup($req->remote_addr, @iprange)) {
        die with Error::Simple("Address-based login endpoint '$id' failed: your address does not match");
    }
    my $xiprange = $config->{exclude_ip_range};
    my @xiprange = ref($xiprange) ? @$xiprange : $xiprange;
    @xiprange = () if @xiprange && !defined $xiprange[0];
    if (Net::CIDR::cidrlookup($req->remote_addr, @xiprange)) {
        die with Error::Simple("Address-based login endpoint '$id' failed: authentication from your address is not permitted");
    }

    my $uauth = Foswiki::UnifiedAuth->new();
    my $db = $uauth->db;

    my $exist = $db->selectrow_array("SELECT COUNT(user_id) FROM users WHERE user_id=?", {}, $config->{user_id});
    if (!$exist) {
        if (!$config->{wiki_name}) {
            die with Error::Simple("Address based login endpoint '$this->{id}' failed: tried to login as a user that does not exist");
        }
        $uauth->add_user('UTF-8', $this->{id}, $config->{user_id}, $config->{wiki_name}, $config->{display_name}, $config->{email} || '');
    }

    return {
        user_id => $config->{user_id},
        data => {}, # probably not needed
    };
}

1;
