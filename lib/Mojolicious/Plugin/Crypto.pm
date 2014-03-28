package Mojolicious::Plugin::Crypto;
{
  $Mojolicious::Plugin::Crypto::VERSION = '0.02';
}

use Crypt::CBC;
use Crypt::PRNG;

use Crypt::Cipher;
use Crypt::Digest::SHA256 qw(sha256 sha256_hex sha256_b64 sha256_b64u
                             sha256_file sha256_file_hex sha256_file_b64 sha256_file_b64u);
use Mojo::Util;
use Mojo::Base 'Mojolicious::Plugin';

our %symmetric_algo = (
  'aes'      => 'Cipher::AES',
  'blowfish' => 'Cipher::Blowfish',
  'des'      => 'Cipher::DES',
  'idea'     => 'Crypt::IDEA',
  '3des'     => 'Crypt::Cipher::DES_EDE',
  'triple_des' => 'Crypt::Cipher::DES_EDE',
  'des_ede'  => 'Crypt::Cipher::DES_EDE',
  'twofish'  => 'Crypt::Cipher::Twofish',
  'xtea'     => 'Crypt::Cipher::XTEA',
  'anubis'   => 'Crypt::Cipher::Anubis',
  'camellia' => 'Crypt::Cipher::Camellia',
  'kasumi'   => 'Crypt::Cipher::KASUMI',
  'khazad'   => 'Crypt::Cipher::Khazad',
  'multi2'   => 'Crypt::Cipher::MULTI2',
  'noekeon'  => 'Crypt::Cipher::Noekeon',
  'rc2'      => 'Crypt::Cipher::RC2',
  'rc5'      => 'Crypt::Cipher::RC5',
  'rc6'      => 'Crypt::Cipher::RC6',
);

sub register {
    my ($self, $app, $args) = @_;
    $args ||= {};

    foreach my $method (qw( _crypt_x _decrypt_x crypt_aes decrypt_aes crypt_blowfish decrypt_blowfish crypt_des decrypt_des 
      crypt_idea decrypt_idea crypt_3des decrypt_3des crypt_twofish decrypt_twofish crypt_xtea decrypt_xtea 
      crypt_anubis decrypt_anubis crypt_camellia decrypt_camellia crypt_kasumi decrypt_kasumi crypt_khazad 
      decrypt_khazad crypt_noekeon decrypt_noekeon crypt_multi2 decrypt_multi2 crypt_rc2 decrypt_rc2 crypt_rc5 
      decrypt_rc5 crypt_rc6 decrypt_rc6 gen_key gen_iv)) {
        $app->helper($method => \&{$method});
    }
}

### Abstract for Crypt_* and Decrypt_* sub
sub _crypt_x {
    my ($self, $algo, $content, $key) = @_;
    $key  = $self->gen_key("sha256") unless ($key);
    my $keypack = pack("H16", $key);
    my $en  = new Crypt::CBC(-key => $keypack, -salt => 1, -cipher => $symmetric_algo{$algo})->encrypt($content);
    my $enh = unpack('H*', $en);
    return ($enh, $key);
}

sub _decrypt_x {
    my ($self, $algo, $cipher_content, $key) = @_; 
    return "" unless ($key);
    my $keypack = pack("H16", $key);
    my $de    = pack('H*', $cipher_content);
    my $clear = new Crypt::CBC(-key => $keypack, -salt => 1, -cipher =>  $symmetric_algo{$algo})->decrypt($de);
    return ($clear, $key);
}

sub gen_key {
    my ($self, $mode) = @_;
    ($mode eq "sha256") ? sha256_hex(_prng(100, "alphanum")) : "NONE";
    ### Todo add more here
}

### generate intialization vector
sub gen_iv {
    my ($self, $byte, $mode) = @_;
    ($mode eq "prng") ? _prng($byte, ""): "";
    ### next time... i will improve stuff for key and iv features
}

sub _prng {
    my ($byte, $mode) = @_;
    my $prng = "";
    
    my $obj_prng = Crypt::PRNG->new;

    if ($mode eq "base64") {
      $prng = $obj_prng->bytes_b64($byte);
    }
    if ($mode eq "hex") {
      $prng = $obj_prng->bytes_hex($byte);
    }
    if ($mode eq "alphanum") {
      $prng = $obj_prng->string($byte);
    } else {
        $prng = $obj_prng->bytes($byte);   
    }

    return $prng;
}

use vars qw($AUTOLOAD);
sub AUTOLOAD {
  my ($self,$c,$k) = @_;
  my $called = $AUTOLOAD =~ s/.*:://r;
  $called =~ m/(.*)_(.*)/;
  my $func = "_".lc($1)."_x";
  return $self->$func(lc($2),$c,$k);
}
sub DESTROY { }

#################### main pod documentation begin ###################

=head1 NAME

Mojolicious::Plugin::Crypto - Provide interface to symmetric cipher algorithms using cipher-block chaining

AES, Blowfish, DES, 3DES, IDEA... and more

=head1 SYNOPSIS

  use Mojolicious::Plugin::Crypt;
  
  my $fix_key = 'secretpassphrase';
  my $plain = "NemuxMojoCrypt";

  #... 
  # You can leave key value empty and it will generate a new key for you

  my ($crypted, $key)  = $t->app->crypt_aes($plain, $fix_key);
  
  #... [ store this crypted data where do you want ... ]
  
  # and decrypt it
  my $clean =  $t->app->decrypt_aes($crypted, $key);
   
=head1 DESCRIPTION

You can use this plugin in order to encrypt and decrypt using one of these algorithms: 

AES (aka Rijndael)
Blowfish
DES
DES_EDE (aka Triple-DES, 3DES)
IDEA
TWOFISH
XTEA
ANUBIS
CAMELLIA
KASUMI
KHAZAD
NOEKEON
MULTI2
RC2
RC5
RC6

=head1 USAGE

=head2 crypt_[ALGO_NAME]() 
  
  call function crypt_ followed by the algo name in lowercase. For example crypt_aes("My Plain Test", "ThisIsMySecretKey")
  ann array will be the return value ('securedata', 'keyused'). 

=head2 decrypt_[ALGO_NAME]()
  
  The same thing for decryption decrypt_ followed by the algo name in lowercase
  Ex.: decrypt_aes("MyCryptedValue","ThisIsMySecretKey") it will return just a scalar value with the plain text. That's all.

=head2 crypt_des_ede(),crypt_3des(),crypt_tripple_des()... 

=head2 methods list (just to write something)

crypt_aes()
crypt_blowfish()
crypt_des()
crypt_3des() [|| crypt_des_ede() || crypt_triple_des()]
crypt_idea()
crypt_twofish()
crypt_xtea();
crypt_anubis();
crypt_camellia();
crypt_kasumi();
crypt_khazad();
crypt_noekeon();
crypt_multi2();
crypt_rc2();
crypt_rc5();
crypt_rc6();

and the same for decrypt functions (please make the effort to put "de" in front of "crypt")

=head2 Retrurn value is an array to make easy a super cryptO call like this... :)

Crypt::

($crypted, $key) = app->crypt_xtea(app->crypt_twofish(app->crypt_idea(app->crypt_3des(app->crypt_blowfish(app->crypt_aes($super_plain,$super_secret))))));

Decrypt::

($plain, $key) = app->decrypt_aes(app->decrypt_blowfish(app->decrypt_3des(app->decrypt_idea(app->decrypt_twofish(app->decrypt_xtea($crypted,$super_secret))))));


=head1 Dummy example using Mojolicious::Lite

  You can test in this way
  
  perl mymojoapp.pl /aes/enc?data=nemux
  perl mymojoapp.pl /aes/dec?data=53616c7465645f5f6355829a809369eee5dfb9489eaee7e190b67d15d2e35ce8

  perl mymojoapp.pl /blowfish/enc?data=nemux
  perl mymojoapp.pl /blowfish/dec?data=53616c7465645f5f16d8c8aa479121d039b04703083a9391

  #!/usr/bin/env perl

  ### All glory to the Hypnotoad

  use Mojolicious::Lite;
  plugin 'Crypto';

  my $bigsecret = "MyNameisMarcoRomano";

  get '/aes/enc' => sub {
    my $self = shift;
    my $data = $self->param('data');
    my ($securedata) = $self->crypt_aes($data, $bigsecret);
    $self->render(text => $securedata);
  };

  get '/aes/dec' => sub {
    my $self = shift;
    my $data = $self->param('data');
    my ($plaintext) = $self->decrypt_aes($data, $bigsecret);
    $self->render(text => $plaintext);
  };

  get '/blowfish/enc' => sub {
    my $self = shift;
    my $data = $self->param('data');
    my ($securedata) = $self->crypt_blowfish($data, $bigsecret);
    $self->render(text => $securedata);
  };

  get '/blowfish/dec' => sub {
    my $self = shift;
    my $data = $self->param('data');
    my ($plaintext) = $self->decrypt_blowfish($data, $bigsecret);
    $self->render(text => $plaintext);
  };

  app->start;

=head1 BUGS

No bugs for now... 

=head1 SUPPORT

Write me if you need some help and feel free to improve it. 
You can find me on irc freenode sometimes. 

=head1 AUTHOR

    Marco Romano
    CPAN ID: NEMUX
    Mojolicious CryptO Plugin
    nemux@cpan.org
    http://search.cpan.org/~nemux/

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

perl(1).

=cut

#################### main pod documentation end ###################


1;
