use Mojo::Base -strict;

use Test::More tests => 5;
use Test::Mojo;
use Mojo::URL;

use Mojolicious::Lite;

BEGIN { use_ok('Mojolicious::Plugin::Crypto') };

sub rndStr{ join'', @_[ map{ rand @_ } 1 .. shift ] }

plugin 'crypto', {};

my $t = Test::Mojo->new(app);

my $hash = "";
$hash = $t->app->sha256_hex("MARCO2");
ok($hash eq "ba2dc2f8d0bb5ab24abdcf35f42b0026aa193dd8d0e52671ebd75063736cf2b3", "Ok $hash");
$hash = $t->app->md5_hex("MARCO2");
ok($hash eq "15be59d85afe10272cf9f32442289524", "Ok $hash");
$hash = $t->app->sha512_file_hex("./listofmypassword.txt");
ok($hash eq "6996d6c3d173c56c80f7756e725b8038a87391e06fda1f05e2d9c6ffed24ac7f4d12cd3892e3672c06e4388bdd81a2febd4a2c65157831189a44f2f11bf724f2", "Ok $hash");
$hash = $t->app->md4_file_hex("./listofmypassword.txt");
ok($hash eq "15d69fa69876c7b3e7652e679d00396a", "Ok $hash");

done_testing(5);


