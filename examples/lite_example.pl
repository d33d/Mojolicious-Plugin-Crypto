#!/usr/bin/env perl

### DUMMY example below and... All the glory to Hypnotoad
use Mojolicious::Lite;
plugin 'Crypto';

my $bigsecret = "MyNameisMarcoRomano";

### You can test in this way
# /aes/enc?data=nemux
# /aes/dec?data=H178172812

# /blowfish/enc?data=nemux
# /blowfish/dec?data=H8172891729812

# /digest/md5?data=nemux
# /digest/sha256?data=nemux

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
