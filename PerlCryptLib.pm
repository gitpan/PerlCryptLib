package PerlCryptLib;

use 5.008;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our $VERSION = '1.03';

##### Returns list containing constants and enumerated constants
sub __symbolList($;$) {
	my $pkg = shift;
	my $filter = shift || '^.*?$';
	my @list = ();
	$pkg = eval('*{' . $pkg . '::}');
	my $count = 0;
	foreach my $key ( sort keys %{$pkg} ) {
		if ($key =~ /$filter/) { 
			my $varname = ${$pkg}{$key};
			$varname =~ s/^\*//;
			#warn "----------------> $key : ", eval($varname), "\n";
			push @list, $key;
		}
	}
	return @list;
}

# Definizione costanti per cryptlib
require 'PerlCryptLib.ph';

# Array dei nomi delle costanti definite in 'PerlCryptLib.ph'
my @CONSTANTS = __symbolList(__PACKAGE__, '^CRYPT_');

# Array dei nomi delle funzioni di cryptlib wrappate
my @FUNCTIONS = qw	(
						cryptStatusError cryptStatusOK
						cryptInitComponents cryptDestroyComponents cryptSetComponent cryptFinalizeComponents
						cryptInit cryptEnd 
						cryptQueryCapability 
						cryptCreateContext cryptDestroyContext cryptDestroyObject 
						cryptGenerateKey cryptGenerateKeyAsync cryptAsyncQuery cryptAsyncCancel 
						cryptEncrypt cryptDecrypt 
						cryptSetAttribute cryptSetAttributeString cryptGetAttribute cryptGetAttributeString cryptDeleteAttribute 
						cryptAddRandom 
						cryptQueryObject 
						cryptExportKey cryptExportKeyEx cryptImportKey cryptImportKeyEx 
						cryptCreateSignature cryptCreateSignatureEx cryptCheckSignature cryptCheckSignatureEx 
						cryptKeysetOpen cryptKeysetClose cryptGetPublicKey cryptGetPrivateKey cryptAddPublicKey cryptAddPrivateKey cryptDeleteKey 
						cryptCreateCert cryptDestroyCert cryptGetCertExtension cryptAddCertExtension cryptDeleteCertExtension cryptSignCert cryptCheckCert cryptImportCert cryptExportCert 
						cryptCAAddItem cryptCAGetItem cryptCADeleteItem cryptCACertManagement 
						cryptCreateEnvelope cryptDestroyEnvelope 
						cryptCreateSession cryptDestroySession 
						cryptPushData cryptFlushData cryptPopData 
						cryptDeviceOpen cryptDeviceClose cryptDeviceQueryCapability cryptDeviceCreateContext 
						cryptLogin cryptLogout 
					);

# Esportazione costanti e funzioni
our @ISA = qw(Exporter);
our @EXPORT_OK = ( @CONSTANTS , @FUNCTIONS );
our @EXPORT = ();
our %EXPORT_TAGS =	( 
						all			=> [ @CONSTANTS , @FUNCTIONS ] ,
						constants	=> [ @CONSTANTS ] ,
						functions	=> [ @FUNCTIONS ]
					);


sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&PerlCryptLib::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('PerlCryptLib', $VERSION);

1;
__END__


=head1 NAME

PerlCryptLib - Perl interface to Peter Guttman's cryptlib API

=head1 DESCRIPTION

PerlCryptLib is an interface module to access cryptlib API.

=over 8

cryptlib (Copyright 1992-2005 Peter Gutmann. All rights reserved.) is a powerful 
encryption and security software toolkit that allows even inexperienced 
crypto-programmers to easily add world-leading encryption and authentication 
services to their software.

For more information about cryptlib features and state-of-the-art, please visit
its official web-site at:

=over 4

=item * http://www.cs.auckland.ac.nz/~pgut001/cryptlib

=back

=back

=head1 PRE-INSTALLATION NOTES

In order to "make" PerlCryptLib properly you need cryptlib source distribution
in your system and you have to modify the pre-processed line in PerlCryptLib.xs:

 #include "../cryptlib322/cryptlib.h"

to point to cryptlib source-directory.

=head1 SYNOPSIS

 use PerlCryptLib qw(:all);

 my $envelope = CRYPT_ENVELOPE;
 if ( cryptInit() == CRYPT_OK ) {
   if ( cryptCreateEnvelope($envelope, 
                            CRYPT_UNUSED, 
                            CRYPT_FORMAT_CRYPTLIB) == CRYPT_OK ) {

     # set some attributes with cryptSetAttribute() or cryptSetAttributeString()
     # set some other crypto-stuff
     # push or pop data with cryptPushData() and cryptPopData()

     cryptDestroyEnvelope($envelope);
   }
   cryptEnd();
 }

=head2 Notes

cryptUIDisplayCert() and cryptUIGenerateKey() cryptlib functions are 
not implemented.

=head1 EXPORT/IMPORT

PerlCryptLib doesn't export anything by default.
You can choose to explicitly import specifics exported tags:

=over 4

=item :constants

all of the CRYPT_* constants and data-types (CRYPT_USER, CRYPT_KEYSET, etc.)

=item :functions

all of the crypt* API functions and macros (cryptInit, cryptImportKey, etc.)

=item :all

all of the cryptlib constants, data-types and functions

=back

For example, to import only function names:

 use PerlCryptLib ':functions';

Alternatively, as usual, you can import such functions or constants by 
specifying each of them in the 'use' statement:

 use PerlCryptLib qw(cryptInit cryptEnd CRYPT_OK);

=head1 CONVENTIONS

=head2 Object-type declaration

=over 4

cryptlib object-handles MUST BE INITIALIZED with the appropriated object-type 
constant (CRYPT_CERTIFICATE, CRYPT_CONTEXT, CRYPT_DEVICE, CRYPT_ENVELOPE, 
CRYPT_KEYSET, CRYPT_SESSION, CRYPT_USER, CRYPT_HANDLE) or, at least, with a
numeric value (generally 0).

So, using

 my $envelope = CRYPT_ENVELOPE;
 my $context = CRYPT_CONTEXT;
 my $certificate = CRYPT_CERTIFICATE;
 
is the same as using

 my $envelope = 0;
 my $context = 0;
 my $certificate = 0;

but is much more comprehensive.

=back

=head2 Pass-by-reference

=over 4

To pass-by-reference cryptlib object-handles, as shown in the above example in 
SYNOPSIS section, don't use the 'back-slash' reference operator ('\').

=back

=head2 Buffers

=over 4

To handle binary buffers (i.e., while enveloping data), you need to initialize 
them "allocating" the needed space, for example using:
 
 my $buffer = ' ' x 1204;

=back

=head2 NULL values

=over 4

NULL values can be handled in different ways:

 # Those three calls are all valid 
 use constant NULL => 0x0;
 $null = 0x0;
 cryptGetPublicKey($cryptKeyset, $cert, CRYPT_KEYID_NONE, 0);
 cryptGetPublicKey($cryptKeyset, $cert, CRYPT_KEYID_NONE, NULL);
 cryptGetPublicKey($cryptKeyset, $cert, CRYPT_KEYID_NONE, $null); 

However, when used in pass-by-reference calls, MUST be declared as 0x0 
scalar values:

 $null = 0x0;
 cryptExportKey($null, 0, $maxLength, $context, $cert);
 $key = ' ' x $maxLength;
 cryptExportKey($key, $maxLength, $keyLength, $context, $cert);

=back

=head2 Accessing low-level components

=over 4

In order to allow the access to low-level components, I've made some small 
changes to the cryptlib macro cryptSetComponent(), for which Perl syntax became:
 
 cryptSetComponent($componentInfo, $element, $source, $length)
 
where $componentInfo is the data-structure itself and $element is the 
data-structure element-name to set.
In addition I've added a NEW low-level macro to retrieve data-structure in
the appropriated format:

 cryptFinalizeComponents($componentInfo, $blob, $size)
  
Here is an example "translated" in PerlCryptLib:
  
 ##### Create objects
 $cryptContext = CRYPT_CONTEXT;
 $rsaKey = CRYPT_PKCINFO_RSA;

 ##### Initialize objects
 cryptCreateContext($cryptContext, $cryptUser, CRYPT_ALGO_RSA);
 cryptSetAttributeString($cryptContext, CRYPT_CTXINFO_LABEL, "RSA key", 7);
 cryptInitComponents($rsaKey, CRYPT_KEYTYPE_PRIVATE);

 ##### Set data-structure elements: note arguments syntax
 cryptSetComponent($rsaKey, 'n', $modulus, 2048);
 cryptSetComponent($rsaKey, 'e', $pubExponent, 17);
 cryptSetComponent($rsaKey, 'd', $privExponent, 2047);
 cryptSetComponent($rsaKey, 'p', $primeFactor1, 1024);
 cryptSetComponent($rsaKey, 'q', $primeFactor2, 1024);
 cryptSetComponent($rsaKey, 'u', $multInverse, 1020);
 cryptSetComponent($rsaKey, 'e1', $privExponent1, 1024);
 cryptSetComponent($rsaKey, 'e2', $privExponent2, 1019);
 
 ##### Finalize component to retrieve data to pass to cryptSetAttributeString
 $rsaKeyBlob = '';
 $rsaKeyBlobSize = 0;
 cryptFinalizeComponents($rsaKey, $rsaKeyBlob, $rsaKeyBlobSize);
 cryptSetAttributeString($cryptContext, CRYPT_CTXINFO_KEY_COMPONENTS,
                         $rsaKeyBlob, $rsaKeyBlobSize );
 
 ##### Destroy objects
 cryptDestroyComponents($rsaKey);
 cryptDestroyContext($cryptContext);

Note: to access single data-structure elements (if really needed) you can do 
as follow:

 print "rsaKey modulus length: ", $rsaKey->{nLen}, "\n";

=back

=head2 Querying objects

=over 4

To query objects such exported keys, signatures or cryptlib capabilities,
you can use standard functions cryptQueryObject() and cryptQueryCapability() 
as follow:

 $cryptObjectInfo = CRYPT_OBJECT_INFO;
 cryptQueryObject($encryptedKey, $encryptedKeyLength, $cryptObjectInfo);
 if ( $cryptObjectInfo->{objectType} == CRYPT_OBJECT_ENCRYPTED_KEY ) {
     warn "Import the key using conventional encryption!", "\n";
 }

 $cryptQueryInfo = CRYPT_QUERY_INFO;
 cryptQueryCapability(CRYPT_ALGO_3DES, $cryptQueryInfo);
 print "Algo-name: ", $cryptQueryInfo->{algoName}, "\n";

=back

=head1 PREREQUIREMENT

=over 4

=item * cryptlib v. 3.2.2

CRYPTLIB Security Toolkit(c) by Peter Guttman

=item * enum-1.016

enum - C style enumerated types and bitmask flags in Perl

=back

=head1 SEE ALSO

Visit Peter Guttman's web site to get latest informations about cryptlib:

=over 4

=item * http://www.cs.auckland.ac.nz/~pgut001/cryptlib/

=back

Visit cryptlib official mailing-list to get support over cryptlib itself:

=over 4

=item * http://news.gmane.org/gmane.comp.encryption.cryptlib

=back

=head1 BUGS AND REQUESTS

Please report any bugs or feature requests to perlcryptlib@gmail.com, or 
through the web interface at http://rt.cpan.org/Public/.
I will be notified, and then you'll automatically be notified of progress on 
your bug as I make changes.

=head1 AUTHOR

Alvaro Livraghi, <perlcryptlib@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 Alvaro Livraghi. All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
