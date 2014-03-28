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