package Perl::Critic::Policy::ErrorHandling::RequireCheckedCalls;

use 5.010001;
use strict;
use warnings;
use Readonly;

use Perl::Critic::Utils qw{ :booleans :characters :severities :classification
                            hashify is_perl_bareword };

use base 'Perl::Critic::Policy';

our $VERSION = '0.000_001';

#-----------------------------------------------------------------------------

Readonly::Scalar my $DESC => q{Return value of %s %s ignored};
Readonly::Scalar my $EXPL => [208, 278];

Readonly::Scalar my $ALL    => ':all';
Readonly::Scalar my $ALL_BUT    => ':all_but';

#-----------------------------------------------------------------------------

sub supported_parameters {
    return (
        {
            name            => 'accept_operators',
            description     =>
                'The set of operators that constitute a check',
            behavior        => 'string list',
            default_string  => 'or',
        },
        {
            name            => 'check_assigned',
            description     => 'Check calls whose value is assigned to a variable',
            behavior        => 'boolean',
            default_string  => $EMPTY,
        },
        {
            name            => 'methods',
            description     =>
                'The set of methods to require checking the return value of.',
            behavior        => 'string list',
        },
        {
            name            => 'subroutines',
            description     =>
                'The set of subroutines to require checking the return value of.',
            behavior        => 'string list',
        },
    );
}

sub default_severity     { return $SEVERITY_MEDIUM       }
sub default_themes       { return qw( trw maintenance )  }
sub applies_to           { return 'PPI::Token::Word'     }

#-----------------------------------------------------------------------------

sub initialize_if_enabled {
    my ( $self ) = @_;

    keys %{ $self->{_methods} }
        or keys %{ $self->{_subroutines} }
        or return $FALSE;

    $self->{_dont_check_assigned} = ! delete $self->{_check_assigned};

    foreach ( keys %{ $self->{_methods} } ) {
        m/ -> /smx
            or next;
        $self->{_static_methods} = $TRUE;
        last;
    }

    foreach ( qw{ methods subroutines } ) {
        my $attr = "_$_";
        my $invert;
        foreach ( $ALL, $ALL_BUT ) {
            delete $self->{$attr}{$_}
                and $invert++;
        }
        $self->{"_check_$_"} = $invert ?
            sub { return ! $self->{$attr}{$_[0]} } :
            sub { return $self->{$attr}{$_[0]} };
    }

    return $TRUE;
}

#-----------------------------------------------------------------------------

sub prepare_to_scan_document {
    my ( $undef, $doc ) = @_;
    $doc->index_locations();
    return $TRUE;
}

#-----------------------------------------------------------------------------

# This code is liberated from Perl::Critic::Utils::is_unchecked_call(), and
# modified to handle both method calls and calls whose return value is
# assigned.
sub violates {
    my ( $self, $elem ) = @_;

    my ( $kind, $name ) = $self->_want_to_check( $elem )
        or return;

    if ( $self->{_dont_check_assigned} ) {
        my $prev_sib = $elem;
        while ( $prev_sib = $prev_sib->sprevious_sibling() ) {
            if ( $prev_sib->isa( 'PPI::Token::Operator' ) ) {
                state $forbid = { hashify qw{ = } };
                $forbid->{ $prev_sib->content() }
                    and return;
            } elsif ( $prev_sib->isa( 'PPI::Token::Word' ) ) {
                state $forbid = { hashify qw{ if unless } };
                $forbid->{ $prev_sib->content() }
                    and return;
            }
        }
    }

    $self->_check_oper( $elem )
        and return;

    $self->_check_statement_parent( $elem )
        and return;

    return $self->violation( sprintf( $DESC, $kind, $name ), $EXPL, $elem );
}

#-----------------------------------------------------------------------------

# Check for things like 'fubar or die'. Return true if found, otherwise return
# false.
sub _check_oper {
    my ( $self, $elem ) = @_;
    my $statement = $elem->statement()
        or return $FALSE;

    my ( $elem_line, $elem_row ) = @{ $elem->location() || [] };
    if ( keys %{ $self->{_accept_operators} } ) {
        foreach my $oper (
            @{ $statement->find( 'PPI::Token::Operator' ) || [] }
        ) {
            # Ensure that the operator comes after the element we're
            # analyzing.
            my ( $oper_line, $oper_row ) = @{ $oper->location() || [] };
            $elem_line > $oper_line
                and next;
            $elem_line == $oper_line
                and $elem_row > $oper_row
                and next;

            $self->{_accept_operators}{ $oper->content() }
                and return $TRUE;
        }
    }
    return $FALSE;
}

#-----------------------------------------------------------------------------

# Miscellaneous checks on the parent of the statement the element is in.
# Return true if one of the checks passes, else return false.
sub _check_statement_parent {
    my ( $self, $elem ) = @_;

    my $parent = $elem->statement()->parent()
        or return $FALSE;

    # Check if we're in an if( open ) {good} else {bad} condition
    return $TRUE if $parent->isa( 'PPI::Structure::Condition' );

    # Return val could be captured in data structure and checked later
    return $TRUE if $parent->isa('PPI::Structure::Constructor') &&
        $self->{_dont_check_assigned};

    # "die if not ( open() )" - It's in list context.
    # FIXME this comes from Perl::Critic::Utils::is_unchecked_call(), but I
    # have my doubts about it.
    return $TRUE if $parent->isa( 'PPI::Structure::List' ) &&
        $parent->sprevious_sibling();

    return $FALSE;
}

#-----------------------------------------------------------------------------

# If we want to check the element, return a two-element list containing the
# kind ('subroutine' or 'method') and the name (content, except for static
# methods which are class->method).
# If we do not want to check the element, return nothing.
sub _want_to_check {
    my ( $self, $elem ) = @_;
    my $name = $elem->content();
    if ( is_method_call( $elem ) ) {
        return( method => $name ) if $self->{_check_methods}->( $name );
        return if ! $self->{_static_methods};
        my $prev_sib = $elem->sprevious_sibling()
            or return;
        # We assume we're a method call, and therefore the previous sibling is
        # '->'. So we don't check.
        $prev_sib = $prev_sib->sprevious_sibling()
            and $prev_sib->isa( 'PPI::Token::Word' )
            or return;
        substr $name, 0, 0, $prev_sib->content() . '->';
        return ( method => $name ) if $self->{_check_methods}->( $name );
    } elsif ( is_function_call( $elem ) ) {
        return( subroutine => $name ) if $self->{_check_subroutines}->( $name );
    }
    return;
}

#-----------------------------------------------------------------------------

1;

__END__

#-----------------------------------------------------------------------------

=pod

=for stopwords autodie

=head1 NAME

Perl::Critic::Policy::ErrorHandling::RequireCheckedCalls - Require checking of the return value of specified subroutines or methods

=head1 AFFILIATION

This Policy is stand-alone, and is not part of the core
L<Perl::Critic|Perl::Critic>.

=head1 DESCRIPTION

This policy is similar to
L<Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls|Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls>,
but is more appropriate to user-written subroutines or methods.

Unlike
L<Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls|Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls>,
this policy is insensitive to the use of L<autodie|autodie> and friends. But
it is sensitive to both subroutines and methods, even when their return values are assigned.

B<Note> that this policy does not look inside interpolations (e.g.
C<"@{[ foo() ]}">) or replacements (e.g.
C<s/ ( \w+ ) / foo( $1 ) /smxge>).

=head1 CONFIGURATION

This policy checks a configurable list of subroutine and method names. These
B<must> be configured, as none are provided by default. If none are specified,
this policy silently disables itself.

=head2 accept_operators

One of the ways to check a call is with a suffix Boolean. By default, only
C<'or'> is accepted. If you want to accept C<'||'> as well, put an entry in
your F<.perlcriticrc> file like this:

    [ErrorHandling::RequireCheckedCalls]
    accept_operators = or ||

B<Note> that if you configure C<'accept_operators'> and want C<'or'> in the
list of accepted operators you must specify it explicitly.

=head2 check_assigned

Normally, values that are assigned are B<not> checked, since the value can
always be checked later, e.g.

    my $value = fubar();
    $value or die;

If you wish to check these, put an entry in your F<.perlcriticrc> file like
this:

    [ErrorHandling::RequireCheckedCalls]
    check_assigned = 1

=head2 subroutines

To configure subroutines, put an entry in your F<.perlcriticrc> file like
this:

    [ErrorHandling::RequireCheckedCalls]
    subroutines = foo bar

The above will check B<only> regular subroutine calls. It will ignore
object-oriented calls to methods C<foo()> or C<bar()>.

In addition to actual subroutines, you can specify C<':all'> to check all
subroutines, or C<':all_but'> to check all subroutines except the named ones.
These are actually equivalent, but saying C<subroutines=:all_but> looks even
stranger than saying C<subroutines=:all foo bar>.

L<Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls|Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls>
has a caveat on the use of its C<:all> selector, and more or less the same
thing applies to this policy. The reason for including them is that I thought
it might be easier to implement them than to explain why their use is a Really
Bad Idea. But the gist of the explanation is simply that not all subroutines
return an error indication.

=head2 methods

To configure methods, put an entry in your F<.perlcriticrc> file like this:

    [ErrorHandling::RequireCheckedCalls]
    methods = foo bar Static->baz

The above will check B<only> object-oriented calls. Regular subroutine calls
to C<foo()> or C<bar()> will be ignored. In addition, C<baz()> will be checked
only if called as a static method on class C<Static>.

You can also specify C<':all'> or C<':all_but'> here. See above under
L<subroutines|/subroutines> for what they do and a little about why you do not
want to use them.

=head1 CREDITS

This module is based on
L<Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls|Perl::Critic::Policy::InputOutput::RequireCheckedSyscalls>,
which was written by Chris Dolan, <cdolan@cpan.org>. That in turn was based on
policies written by Andrew Moore, <amoore@mooresystems.com>.

=head1 AUTHOR

Thomas R. Wyant, III F<wyant at cpan dot org>

=head1 COPYRIGHT

Copyright (C) 2024 Thomas R. Wyant, III

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl 5.10.1. For more details, see the full text
of the licenses in the directory LICENSES.

This program is distributed in the hope that it will be useful, but
without any warranty; without even the implied warranty of
merchantability or fitness for a particular purpose.

=cut

##############################################################################
# Local Variables:
#   mode: cperl
#   cperl-indent-level: 4
#   fill-column: 78
#   indent-tabs-mode: nil
#   c-indentation-style: bsd
# End:
# ex: set ts=8 sts=4 sw=4 tw=78 ft=perl expandtab shiftround :
