package Mojolicious::Plugin::Crypto;
{
  $Mojolicious::Plugin::Crypto::VERSION = '0.01';
}

use Crypt::CBC;
use Crypt::OpenSSL::AES;

use Crypt::Cipher;
use Crypt::Digest::SHA256 qw(sha256 sha256_hex sha256_b64 sha256_b64u
                             sha256_file sha256_file_hex sha256_file_b64 sha256_file_b64u);
use Mojo::Util;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.01';
$VERSION = eval $VERSION;

sub register {
    my ($self, $app, $args) = @_;
    $args ||= {};

    foreach my $method (qw( crypt_aes crypt_blowfish decrypt_blowfish gen_key gen_iv decrypt_aes )) {
        $app->helper($method => \&{$method});
    }
}

## Symetric cipher AES (aka Rijndael), key size: 256 bits
sub crypt_aes {
    my ($self, $content, $key) = @_;
    $key = $self->gen_key("sha256") unless ($key);

    my $en  = new Crypt::CBC(-key => $key, -cipher => 'Crypt::OpenSSL::AES')->encrypt($content);
    my $enh = unpack('H*', $en);

    return ($enh, $key);
}

sub decrypt_aes {
    my ($self, $cipher_content, $key) = @_; 
    return "" unless ($key);
    my $de = pack('H*', $cipher_content);
    my $clear = new Crypt::CBC(-key => $key, -cipher => 'Crypt::OpenSSL::AES')->decrypt($de);
    return $clear;
}

##  Symetric cipher Blowfish, key size: 448 bits
sub crypt_blowfish {
    my ($self, $content, $key) = @_;
    $key = $self->gen_key("sha256") unless ($key);
    $key = pack("H16", $key);
    my $en  = new Crypt::CBC(-key => $key, -cipher => 'Crypt::Cipher::Blowfish')->encrypt($content);
    my $enh = unpack('H*', $en);
    return ($enh, $key);
}

sub decrypt_blowfish {
    my ($self, $cipher_content, $key) = @_; 
    return "" unless ($key);
    $key = pack("H16", $key);;
    my $de = pack('H*', $cipher_content);
    my $clear = new Crypt::CBC(-key => $key, -cipher => 'Crypt::Cipher::Blowfish')->decrypt($de);
    return $clear;
}

####### Some Stuff #######

### Generate 256 bit key using sha
sub gen_key {
    my ($self, $mode) = @_;
    ($mode eq "sha256") ? sha256_hex(_prng(100, "alphanum")) : "NONE";
    ### Todo add more here
}

### generate intialization vector
sub gen_iv {
    my ($self, $byte, $mode) = @_;
    ($mode eq "prng") ? _prng($byte, ""): "";
    ### TODO Add here
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

#################### main pod documentation begin ###################
## Below is the stub of documentation for your module. 


=head1 NAME

Mojolicious::Plugin::Crypto - Provide interface to symmetric cipher algorithms (AES and Blowfish)

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

You can use this plugin in order to encrypt and decrypt value using one of these two symmetric algorithms: AES or Blowfish

=head1 USAGE

#!/usr/bin/env perl

### DUMMY example below and... All the glory to the Hypnotoad
use Mojolicious::Lite;
plugin 'Crypto';

my $bigsecret = "MyNameisMarcoRomano";

### You can test in this way
# /aes/enc?data=nemux
# /aes/dec?data=53616c7465645f5f6355829a809369eee5dfb9489eaee7e190b67d15d2e35ce8

# /blowfish/enc?data=nemux
# /blowfish/dec?data=53616c7465645f5f16d8c8aa479121d039b04703083a9391

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

No bugs for now... but there are more features to add in the future. Probably... 

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
# The preceding line will help the module return a true value

