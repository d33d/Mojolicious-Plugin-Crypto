#!/usr/bin/env perl
use Mojolicious::Lite;

plugin 'Crypto', {
  symmetric_cipher => 1,
  digest           => 1,
  mac              => 1,
};

my $bigsecret = "MyNameisMarcoRomano";
my $hmac_key  = "SECRETOK";
### You can test in this way
# /aes/enc?data=nemux
# /aes/dec?data=H178172812

# /blowfish/enc?data=nemux
# /blowfish/dec?data=H8172891729812

# /digest/md5?data=nemux
# /digest/sha256?data=nemux

# /hmac/sha256?data=nemux

get '/hmac/sha256' => sub {
  my $self = shift;
  my $data = $self->param('data');
  my $hex_hmac = $self->hmac_hex('SHA256', $hmac_key, $data);
  $self->render(text => $hex_hmac);
};

get '/digest/sha256' => sub {
  my $self = shift;
  my $data = $self->param('data');
  my $hex_digest = $self->sha256_hex($data);
  $self->render(text => $hex_digest);
};

get '/digest/md5' => sub {
  my $self = shift;
  my $data = $self->param('data');
  my ($hex_digest) = $self->md5_hex($data);
  $self->render(text => $hex_digest);
};

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
