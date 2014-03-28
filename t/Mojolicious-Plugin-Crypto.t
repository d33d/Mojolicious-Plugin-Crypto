use Mojo::Base -strict;

use Test::More tests => 5;
use Test::Mojo;
use Mojo::URL;

use Mojolicious::Lite;

BEGIN { use_ok('Mojolicious::Plugin::Crypto') };

plugin 'crypto', {};

my $t = Test::Mojo->new(app);

my $fix_key = 'secretpassphrase';
my $plain = "NemuxMojoCrypt";

my $blow_key   = "MyNameisMarcoRomano";
my $blow_plain = "nemux";

my ($crypted, $key)  = $t->app->crypt_aes($plain, $fix_key);
ok($key eq $fix_key, "AES return KEY");
my $clean =  $t->app->decrypt_aes($crypted, $key);
ok($plain eq $clean, "AES ENC/DEC");
($crypted, $key)  = $t->app->crypt_blowfish($blow_plain, $blow_key);
ok($key eq pack("H16", $blow_key), "Blowfish return KEY");
my $clean_blow =  $t->app->decrypt_blowfish($crypted, $blow_key);
ok($blow_plain eq $clean_blow, "Blowfish ENC/DEC expected $blow_plain i got $clean_blow");
done_testing(5);