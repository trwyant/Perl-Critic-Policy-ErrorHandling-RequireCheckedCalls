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

Readonly::Scalar my $DEREF  => q/->/;

#-----------------------------------------------------------------------------

sub supported_parameters {
    return (
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

    $self->{_dont_check_assigned} = ! delete $self->{_check_assigned};

    if ( keys %{ $self->{_methods} } ) {
        foreach ( keys %{ $self->{_methods} } ) {
            m/ -> /smx
                or next;
            $self->{_static_methods} = $TRUE;
            last;
        }
        return $TRUE;
    } else {
        return keys %{ $self->{_subroutines} } ? $TRUE : $FALSE;
    }
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

    if ( my $statement = $elem->statement() ) {

        # "open or die" is OK.
        # We can't check snext_sibling for 'or' since the next siblings can be
        # an unknown number of arguments to the call. Instead, check all of
        # the elements to this statement to see if we find 'or', '||, or '//'.
        # Unlike Perl::Critic::Utils::is_unchecked_call(), we do not check for
        # '|'.

        my $or_operators = sub  {
            my ( undef, $elem ) = @_;  ## no critic(Variables::ProhibitReusedNames)
            state $or_or_or = { hashify( qw( or || // ) ) };
            return $elem->isa( 'PPI::Token::Operator' ) &&
                $or_or_or->{ $elem->content() };
        };

        return if $statement->find( $or_operators );

        if( my $parent = $elem->statement()->parent() ){

            # Check if we're in an if( open ) {good} else {bad} condition
            return  if $parent->isa('PPI::Structure::Condition');

            # Return val could be captured in data structure and checked later
            return if $parent->isa('PPI::Structure::Constructor') &&
                $self->{_dont_check_assigned};

            # "die if not ( open() )" - It's in list context.
            if ( $parent->isa('PPI::Structure::List') ) {
                if( my $uncle = $parent->sprevious_sibling() ){
                    return if $uncle;
                }
            }
        }
    }

    return $self->violation( sprintf( $DESC, $kind, $name ), $EXPL, $elem );
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
        return( method => $name ) if $self->{_methods}{$name};
        return if ! $self->{_static_methods};
        my $prev_sib = $elem->sprevious_sibling()
            or return;
        # We assume we're a method call, and therefore the previous sibling is
        # '->'. So we don't check.
        $prev_sib = $prev_sib->sprevious_sibling()
            and $prev_sib->isa( 'PPI::Token::Word' )
            or return;
        substr $name, 0, 0, $prev_sib->content() . '->';
        return ( method => $name ) if $self->{_methods}{$name};
    } elsif ( is_function_call( $elem ) ) {
        return( subroutine => $name ) if $self->{_subroutines}{$name};
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

Normally, values that are assigned are B<not> checked, since the value can
always be checked later, e.g.

 my $value = fubar();
 $value or die;

If you wish to check these, put an entry in a F<.perlcriticrc> file like this:

    [ErrorHandling::RequireCheckedCalls]
    check_assigned = 1

To configure subroutines, put an entry in a F<.perlcriticrc> file like this:

    [ErrorHandling::RequireCheckedCalls]
    subroutines = foo bar

The above will check B<only> regular subroutine calls. It will ignore
object-oriented calls to methods C<foo()> or C<bar()>.

To configure methods, put an entry in a F<.perlcriticrc> file like this:

    [ErrorHandling::RequireCheckedCalls]
    methods = foo bar Static->baz

The above will check B<only> object-oriented calls. Regular subroutine calls
to C<foo()> or C<bar()> will be ignored. In addition, C<baz()> will be checked
only if called as a static method on class C<Static>.

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
