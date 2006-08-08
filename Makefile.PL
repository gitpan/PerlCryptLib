use 5.008;
use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'			=>	'PerlCryptLib',
	'DISTNAME'		=>	'PerlCryptLib',
	'VERSION_FROM'	=>	'PerlCryptLib.pm',
	'PREREQ_PM'		=>	{ 'enum' => '1.016' },
    'PM'            =>	{ 
							'PerlCryptLib.pm' => '$(INST_LIBDIR)/PerlCryptLib.pm',
							'PerlCryptLib.ph' => '$(INST_LIBDIR)/PerlCryptLib.ph'
						},
 	(
		$] >= 5.005 ?
						(
							ABSTRACT	=> 'PerlCryptLib - Perl interface to Peter Guttman\'s cryptlib API',
							AUTHOR		=> 'Alvaro Livraghi <perlcryptlib@gmail.com>'
						) : 
						()
	),
	'LIBS'			=>	['-lcl -lresolv -lpthread'],
	'DEFINE'		=>	'',
	'INC'			=>	'-I.',
	'realclean'		=>	{
							FILES	=> '*.inc',
						},
);

if  (eval {require ExtUtils::Constant; 1}) {

	my @names = ();
	ExtUtils::Constant::WriteConstants	(
											NAME         => 'PerlCryptLib',
											NAMES        => \@names,
											DEFAULT_TYPE => 'IV',
											C_FILE       => 'const-c.inc',
											XS_FILE      => 'const-xs.inc',
										);

} else {

	use File::Copy;
	use File::Spec;
	foreach my $file ('const-c.inc', 'const-xs.inc') {
		my $fallback = File::Spec->catfile('fallback', $file);
		copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
	}

}
