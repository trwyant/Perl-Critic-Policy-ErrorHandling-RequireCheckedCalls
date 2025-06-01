use strict;
use warnings;

use 5.008008;

use lib qw{ inc };

use ExtUtils::MakeMaker;
use My::Module::Meta qw{
    build_required_module_versions
    meta_merge
    required_module_versions
    requires_perl
    recommended_module_versions
};

( my $mmv = ExtUtils::MakeMaker->VERSION ) =~ s/_//g;

my %args = (
    NAME            => 'Perl::Critic::Policy::ErrorHandling::RequireCheckedCalls',
    VERSION_FROM    => 'lib/Perl/Critic/Policy/ErrorHandling/RequireCheckedCalls.pm',
    PREREQ_PM       => { required_module_versions() },
    PL_FILES        => {},        # Prevent old MakeMaker from running Build.PL
    AUTHOR          => 'Tom Wyant (wyant at cpan dot org)',
    ABSTRACT        => 'Critique unchecked function calls',
);

$mmv >= 6.31
    and $args{LICENSE} = 'perl';

$mmv >= 6.4501
    and $args{META_MERGE} = meta_merge();

$mmv >= 6.4701
    and $args{MIN_PERL_VERSION} = requires_perl();

$mmv >= 6.5501
    and $args{BUILD_REQUIRES} = { build_required_module_versions() }
    or $mmv >= 6.4501
    and $args{META_MERGE}{build_requires} = { build_required_module_versions() };

WriteMakefile( %args );

##############################################################################
# Local Variables:
#   mode: cperl
#   cperl-indent-level: 4
#   fill-column: 78
#   indent-tabs-mode: nil
#   c-indentation-style: bsd
# End:
# ex: set ts=8 sts=4 sw=4 tw=78 ft=perl expandtab shiftround :
