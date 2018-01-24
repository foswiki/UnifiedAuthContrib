package Foswiki::UnifiedAuth;

use strict;
use warnings;
use utf8;

use DBI;
use Encode;

use Foswiki::Users::BaseUserMapping;
Foswiki::Users::BaseUserMapping->new($Foswiki::Plugins::SESSION) if $Foswiki::Plugins::SESSION;
my $bu = \%Foswiki::Users::BaseUserMapping::BASE_USERS;

my @schema_updates = (
    [
        "CREATE TABLE meta (type TEXT NOT NULL UNIQUE, version INT NOT NULL)",
        "INSERT INTO meta (type, version) VALUES('core', 0)",
        "CREATE TABLE users (
            user_id TEXT NOT NULL PRIMARY KEY,
            wiki_name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            email TEXT NOT NULL
        )",
        "INSERT INTO users (user_id, wiki_name, display_name, email)
            VALUES('BaseUserMapping_111', 'ProjectContributor', 'Project Contributor', ''),
            ('BaseUserMapping_222', '$bu->{BaseUserMapping_222}{wikiname}', 'Registration Agent', ''),
            ('BaseUserMapping_333', '$bu->{BaseUserMapping_333}{wikiname}', 'Internal Admin User', '$bu->{BaseUserMapping_333}{email}'),
            ('BaseUserMapping_666', '$bu->{BaseUserMapping_666}{wikiname}', 'Guest User', ''),
            ('BaseUserMapping_999', 'UnknownUser', 'Unknown User', '')",
        "CREATE UNIQUE INDEX users_wiki_name ON users (wiki_name)",
        "CREATE INDEX users_email ON users (email)",
        "CREATE TABLE user_mappings (
            user_id TEXT NOT NULL,
            mapper_id TEXT NOT NULL,
            mapped_id TEXT NOT NULL,
            PRIMARY KEY (user_id, mapper_id, mapped_id),
            UNIQUE (mapper_id, mapped_id)
        )",
        "INSERT INTO user_mappings (user_id, mapper_id, mapped_id)
            VALUES('BaseUserMapping_111', 'Foswiki::Users::BaseUserMapping', 'ProjectContributor'),
            ('BaseUserMapping_222', 'Foswiki::Users::BaseUserMapping', '$bu->{BaseUserMapping_222}{login}'),
            ('BaseUserMapping_333', 'Foswiki::Users::BaseUserMapping', '$bu->{BaseUserMapping_333}{login}'),
            ('BaseUserMapping_666', 'Foswiki::Users::BaseUserMapping', '$bu->{BaseUserMapping_666}{login}'),
            ('BaseUserMapping_999', 'Foswiki::Users::BaseUserMapping', 'unknown')",
        "CREATE TABLE groups (
            group_id TEXT NOT NULL PRIMARY KEY,
            description TEXT
        )",
        "CREATE TABLE group_members (
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id)
        )",
        "CREATE INDEX group_members_user_id ON group_members (user_id)",
    ],
    [
        "ALTER TABLE groups ADD COLUMN mapper_id TEXT",
        "ALTER TABLE group_members ADD COLUMN mapper_id TEXT",
        "CREATE TABLE group_mappings (
            group_id TEXT NOT NULL,
            mapper_id TEXT NOT NULL,
            mapped_id TEXT NOT NULL,
            PRIMARY KEY (group_id, mapper_id, mapped_id),
            UNIQUE (mapper_id, mapped_id)
        )",
    ],
);

my $singleton;

sub new {
    my ($class) = @_;
    return $singleton if $singleton;
    my $this = bless {}, $class;

    $singleton = $this;
}

sub finish {
    undef $singleton->{db} if $singleton;
    undef $singleton;
}

sub db {
    my $this = shift;
    $this->connect unless defined $this->{db};
    $this->{db};
}

sub connect {
    my $this = shift;
    return $this->{db} if defined $this->{db};
    my $db = DBI->connect($Foswiki::cfg{UnifiedAuth}{MappingDSN} || "DBI:SQLite:dbname=$Foswiki::cfg{DataDir}/UnifiedAuth.db",
        $Foswiki::cfg{UnifiedAuth}{MappingDBUsername} || '',
        $Foswiki::cfg{UnifiedAuth}{MappingDBPassword} || '',
        {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1,
        }
    );
    $this->{db} = $db;
    $this->{schema_versions} = {};
    eval {
        $this->{schema_versions} = $db->selectall_hashref("SELECT * FROM meta", 'type', {});
    };
    $this->apply_schema('core', @schema_updates);
}

sub apply_schema {
    my $this = shift;
    my $type = shift;
    my $db = $this->{db};
    if (!$this->{schema_versions}{$type}) {
        $this->{schema_versions}{$type} = { version => 0 };
    }
    my $v = $this->{schema_versions}{$type}{version};
    return if $v >= @_;
    for my $schema (@_[$v..$#_]) {
        $db->begin_work;
        for my $s (@$schema) {
            if (ref($s) eq 'CODE') {
                $s->($db);
            } else {
                $db->do($s);
            }
        }
        $db->do("UPDATE meta SET version=? WHERE type=?", {}, ++$v, $type);
        $db->commit;
    }
}

my %normalizers = (
    de => sub {
        my $wn = shift;
        $wn =~ s/Ä/Ae/g;
        $wn =~ s/Ö/Oe/g;
        $wn =~ s/Ü/Ue/g;
        $wn =~ s/ä/ae/g;
        $wn =~ s/ö/oe/g;
        $wn =~ s/ü/ue/g;
        $wn =~ s/ß/ss/g;
        $wn;
    }
);

sub add_user {
    my $this = shift;
    my ($charset, $authdomainid, $loginid, $wikiname, $display_name, $email) = @_;
    my $orig_loginid = $loginid;

    _uni($charset, $loginid, $wikiname, $display_name, $email);

    my $existing;
    my $db = $this->db;

    my (%ids, %wikinames);
    my ($rewrite_id, $rewrite_wn);

    $loginid =~ s/([^a-z0-9])/'_'.sprintf('%02x', ord($1))/egi;
    my @normalizers = split(/\s*,\s*/, $Foswiki::cfg{UnifiedAuth}{WikiNameNormalizers} || '');
    foreach my $n (@normalizers) {
        next if $n =~ /^\s*$/;
        $wikiname = $normalizers{$n}->($wikiname);
    }
    eval {
        require Text::Unidecode;
        $wikiname = Text::Unidecode::unidecode($wikiname);
    };
    $wikiname =~ s/([^a-z0-9])//gi;
    $wikiname =~ s/^([a-z])/uc($1)/e;

    my $rewrite_short = $Foswiki::cfg{UnifiedAuth}{ShortIDs} || 0;
    my $id_from_wn = $Foswiki::cfg{UnifiedAuth}{WikiNameIDs} || 0;
    my $id_serial = $Foswiki::cfg{UnifiedAuth}{ShortIDIncrement} || 0;

    $loginid = $wikiname if $id_from_wn;

    my $has = sub {
        my $id = shift;
        return $db->selectrow_array("SELECT COUNT(user_id) FROM users WHERE user_id=?", {}, $id);
    };
    if (!$rewrite_short || !$id_serial && $has->($loginid)) {
        $loginid = "${authdomainid}_$loginid";
    } else {
        $loginid =~ s/^([^a-z])/x_xx$1/i;
    }
    my $fixedid = $loginid;
    my $serial = 1;
    while ($has->($fixedid)) {
        $fixedid = $loginid . $serial++;
    }
    $loginid = $fixedid;

    $has = sub {
        my $wn = shift;
        return $db->selectrow_array("SELECT COUNT(wiki_name) FROM users WHERE wiki_name=?", {}, $wn);
    };
    $fixedid = $wikiname;
    $serial = 1;
    while ($has->($fixedid)) {
        $fixedid = $wikiname . $serial++;
    }
    $wikiname = $fixedid;

    if (!$loginid || !$wikiname) {
        die "Could not determine a unique login ID and/or internal name for the $authdomainid account '$loginid'";
    }

    $this->{db}->do("INSERT INTO users (user_id, wiki_name, display_name, email) VALUES(?,?,?,?)", {},
        $loginid, $wikiname, $display_name, $email
    );
    return $loginid;
}

sub _uni {
    my $charset = shift;
    for my $i (@_) {
        next if utf8::is_utf8($i);
        $i = decode($charset, $i);
    }
}

sub update_user {
    my ($this, $charset, $loginid, $display_name, $email) = @_;
    _uni($charset, $loginid, $display_name, $email);
    return $this->db->do("UPDATE users SET display_name=?, email=? WHERE user_id=?", {}, _uni($charset, $display_name), $email, $loginid);
}

sub handleScript {
    my $session = shift;

    my $req = $session->{request};
    # TODO
}

1;
