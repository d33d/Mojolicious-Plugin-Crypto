package Mojolicious::Plugin::Crypto;
{
  $Mojolicious::Plugin::Crypto::VERSION = '0.03';
}

use Crypt::CBC;
use Crypt::PRNG;

use Crypt::Cipher;
use Crypt::Digest::SHA256;
use Crypt::Digest::SHA512;
use Crypt::Digest::MD5 qw( md5 md5_hex md5_b64 md5_b64u md5_file md5_file_hex md5_file_b64 md5_file_b64u );
use Crypt::Digest::Whirlpool qw( whirlpool whirlpool_hex whirlpool_b64 whirlpool_b64u whirlpool_file whirlpool_file_hex whirlpool_file_b64 whirlpool_file_b64u );
use Crypt::Digest::SHA1 qw( sha1 sha1_hex sha1_b64 sha1_b64u sha1_file sha1_file_hex sha1_file_b64 sha1_file_b64u );
use Crypt::Digest::CHAES qw( chaes chaes_hex chaes_b64 chaes_b64u chaes_file chaes_file_hex chaes_file_b64 chaes_file_b64u );
use Crypt::Digest::MD2 qw( md2 md2_hex md2_b64 md2_b64u md2_file md2_file_hex md2_file_b64 md2_file_b64u );
use Crypt::Digest::MD4 qw( md4 md4_hex md4_b64 md4_b64u md4_file md4_file_hex md4_file_b64 md4_file_b64u );
use Crypt::Digest::RIPEMD128 qw( ripemd128 ripemd128_hex ripemd128_b64 ripemd128_b64u ripemd128_file ripemd128_file_hex ripemd128_file_b64 ripemd128_file_b64u );
use Crypt::Digest::RIPEMD160 qw( ripemd160 ripemd160_hex ripemd160_b64 ripemd160_b64u ripemd160_file ripemd160_file_hex ripemd160_file_b64 ripemd160_file_b64u );
use Crypt::Digest::RIPEMD256 qw( ripemd256 ripemd256_hex ripemd256_b64 ripemd256_b64u ripemd256_file ripemd256_file_hex ripemd256_file_b64 ripemd256_file_b64u );
use Crypt::Digest::RIPEMD320 qw( ripemd320 ripemd320_hex ripemd320_b64 ripemd320_b64u ripemd320_file ripemd320_file_hex ripemd320_file_b64 ripemd320_file_b64u );
use Crypt::Digest::SHA224 qw( sha224 sha224_hex sha224_b64 sha224_b64u sha224_file sha224_file_hex sha224_file_b64 sha224_file_b64u );
use Crypt::Digest::SHA384 qw( sha384 sha384_hex sha384_b64 sha384_b64u sha384_file sha384_file_hex sha384_file_b64 sha384_file_b64u );
use Crypt::Digest::Tiger192 qw( tiger192 tiger192_hex tiger192_b64 tiger192_b64u tiger192_file tiger192_file_hex tiger192_file_b64 tiger192_file_b64u );

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

our @hash_algo = (
  'Crypt::Digest::SHA256', 'Crypt::Digest::SHA1', 'Crypt::Digest::CHAES',
  'Crypt::Digest::SHA512','Crypt::Digest::MD5', 'Crypt::Digest::Whirlpool',
  'Crypt::Digest::RIPEMD320', 'Crypt::Digest::MD2', 'Crypt::Digest::MD4', 
  'Crypt::Digest::RIPEMD128', 'Crypt::Digest::RIPEMD160', 'Crypt::Digest::RIPEMD256', 
  'Crypt::Digest::SHA224', 'Crypt::Digest::SHA384', 'Crypt::Digest::Tiger192'
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

    map { $app->helper($method => \&{$_}) } map { $_ ~~ /^sha|md5|md4|md2|ripemd|tiger|whirlpool.*/ ? $_ : () } map { lm($_) } @hash_algo;
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

sub lm {
    my $module = shift;
    no strict 'refs';
    return grep { defined &{"$module\::$_"} } keys %{"$module\::"}
}

use vars qw($AUTOLOAD);
sub AUTOLOAD {
  my ($self,$c,$k) = @_;
  my $called = $AUTOLOAD =~ s/.*:://r;
  return $called($c) unless ($called ~~ /^sha.*/);

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

=head2 Symmetric algorithms supported 

You can use this plugin in order to encrypt and decrypt using one of these algorithms: 

=over 4

=item * B<AES (aka Rijndael)>
=item * B<Blowfish>
=item * B<DES>
=item * B<DES_EDE (aka Triple-DES, 3DES)>
=item * B<IDEA>
=item * B<TWOFISH>
=item * B<XTEA>
=item * B<ANUBIS>
=item * B<CAMELLIA>
=item * B<KASUMI>
=item * B<KHAZAD>
=item * B<NOEKEON>
=item * B<MULTI2>
=item * B<RC2>
=item * B<RC5>
=item * B<RC6>

=head1 USAGE

=head2 crypt_[ALGO_NAME]() 
  
  call function crypt_ followed by the lowercase algorithms name. For example crypt_aes("My Plain Test", "ThisIsMySecretKey")
  an array will be the return value with ('securedata', 'keyused'). 

=head2 decrypt_[ALGO_NAME]()
  
  The same thing for decryption decrypt_ followed by the algorithms name in lowercase
  Ex.: decrypt_aes("MyCryptedValue","ThisIsMySecretKey") it will return an array with two values: 
  the first one is the clear text decrypted and the last one the key used. That's all.

=head2 methods list 

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

and the same for decrypt functions (please make the effort to put "de" in front of "crypt_[name]")

=head2 3DES: Multiple names, same result 

=over 4

=item 1 L<crypt_des_ede()>
=item 2 L<crypt_3des()>,
=item 3 L<crypt_tripple_des()>

=head2 nested calls

=over 4

=item * B<Crypt>

=back 

($crypted, $key) = app->crypt_xtea(app->crypt_twofish(app->crypt_idea(app->crypt_3des(app->crypt_blowfish(app->crypt_aes($super_plain,$super_secret))))));

=item * B<Decrypt>

=back

($plain, $key) = app->decrypt_aes(app->decrypt_blowfish(app->decrypt_3des(app->decrypt_idea(app->decrypt_twofish(app->decrypt_xtea($crypted,$super_secret))))));

=head1 Dummy example using Mojolicious::Lite

  You can test in this way
  
  perl mymojoapp.pl /aes/enc?data=nemux
  perl mymojoapp.pl /aes/dec?data=53616c7465645f5f6355829a809369eee5dfb9489eaee7e190b67d15d2e35ce8

  perl mymojoapp.pl /blowfish/enc?data=nemux
  perl mymojoapp.pl /blowfish/dec?data=53616c7465645f5f16d8c8aa479121d039b04703083a9391

  #!/usr/bin/env perl

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

=head1 TODO

=over 4

=item * Hash functions
=item * Random numbers generator
=item * Asymmetric algorithms

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
