# See bottom of file for license and copyright information

=begin TML

---+ package Foswiki::Users::UnifiedPasswdUser

Unified password manager that can draw from multiple sources.

=cut

package Foswiki::Users::UnifiedPasswdUser;
use strict;
use warnings;

use Foswiki::Users::Password ();
our @ISA = ('Foswiki::Users::Password');

use Assert;
use Error qw( :try );
use Fcntl qw( :DEFAULT :flock );

sub new {
    my ( $class, $session ) = @_;
    my $this = bless( $class->SUPER::new($session), $class );
    $this->{error} = undef;

    return $this;
}

# Note to developers; please undef *all* fields in the object explicitly,
# whether they are references or not. That way this method is "golden
# documentation" of the live fields in the object.
sub finish {
    my $this = shift;
    $this->SUPER::finish();
}

sub readOnly {
    return 0;
}

sub canFetchUsers {
    # TODO make dynamic
    return 0;
}

sub fetchPass {
    my ( $this, $login ) = @_;
    # TODO
    $this->{error} = "Can't fetch password information in this implementation";
    return;
}

sub setPassword {
    my ( $this, $login, $newUserPassword, $oldUserPassword ) = @_;
    # TODO
    $this->{error} = "Can't change passwords in this implementation";
    return;
}

sub removeUser {
    my ( $this, $login ) = @_;
    # TODO
    $this->{error} = "Cannot remove users in this implementation";
    return;
}

sub checkPassword {
    my ( $this, $login, $password ) = @_;
    # TODO
    $this->{error} = "Cannot check passwords in this implementation";
    return;
}

sub isManagingEmails {
    return 0;
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2010 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

Additional copyrights apply to some or all of the code in this
file as follows:

Copyright (C) 1999-2007 Peter Thoeny, peter@thoeny.org
and TWiki Contributors. All Rights Reserved. TWiki Contributors
are listed in the AUTHORS file in the root of this distribution.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

