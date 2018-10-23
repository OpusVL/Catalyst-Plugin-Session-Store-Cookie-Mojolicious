package Catalyst::Plugin::Session::Store::Cookie::Mojolicious;
use strict;
use warnings;
use v5.24;

# ABSTRACT: Cross-compatibility with Mojolicious session cookies

use Moose;
use Mojo::Util qw(b64_decode b64_encode);
use Mojo::JSON;
use Scalar::IfDefined qw/$ifdef/;

extends 'Catalyst::Plugin::Session::Store';
with 'Catalyst::ClassData';

# Cargo-culted from Mojolicious::Sessions and
# Catalyst::Plugin::Session::Store::Cookie

our $VERSION = '0.001';

__PACKAGE__->mk_classdata($_)
  for qw/_store_cookie_name _store_cookie_expires _secret/;

use Data::Dump 'pp';

sub get_session_data {
    my $self = shift;
    my $key = shift;
    $key =~ s/:.+//;

    say "Retrieve session data $key";
    $self->_needs_early_session_finalization(1);
    my $cookie = $self->req->cookie($self->_store_cookie_name);
    my $value = $cookie->$ifdef('value');

    if (defined $value) {
        say "Found cookie $value";
        if ($value =~ s/--([^\-]+)$//) {
            my $signature = $1;
            my $check = $self->_checksum($value);
            unless (Mojo::Util::secure_compare($check, $signature)) {
                $self->log->debug("Cookie " . $self->_store_cookie_name . " has a bad signature");
                undef $value;
            }
        }
        else {
            $self->log->debug("Cookie " . $self->_store_cookie_name . " has no signature");
        }
    }
    else {
        $self->log->debug("Cookie " . $self->_store_cookie_name . " not set");
    }

    $self->{__cookie_session_store_cache__} =
        $self->_decode_session_data($value) // {};

    say "Deserialised: " . pp $self->{__cookie_session_store_cache__};
    return $self->{__cookie_session_store_cache__}->{$key};
}

sub store_session_data {
    my $self = shift;
    my $key  = shift;
    my $data = shift;
    $key =~ s/:.+//;

    $self->{__cookie_session_store_cache__}->{$key} = $data;

    say "Store session data $key = " . pp $data;

    my $options = {
        expires  => $self->_store_cookie_expires,
    };

    my $enc = $self->_encode_session_data($self->{__cookie_session_store_cache__}, $options);
    my $checksum = $self->_checksum($enc);
    my $value = "$enc--$checksum";
    $self->res->cookies->{$self->_store_cookie_name} = {
        value => $value,
        %$options
    };

}

sub delete_session_data {
    my ($self, $key) = @_;
    $key =~ s/:.+//;
    delete $self->{__cookie_session_store_cache__}->{$key};
}

sub setup_session {
  my $class = shift;
  my $cfg = $class->_session_plugin_config;
  $class->_store_cookie_name($cfg->{storage_cookie_name} || Catalyst::Utils::appprefix($class) . '_store');
  $class->_store_cookie_expires($cfg->{storage_cookie_expires} || '+1d');

  warn "You didn't set your storage_secret for cookie storage! This has to match your Mojo app."
    if not $cfg->{storage_secret};
  $class->_secret($cfg->{storage_secret} || 'changeme');

  return $class->maybe::next::method(@_);
}

sub _encode_session_data {
    my $self = shift;
    my $data = shift;
    my $opts = shift;

    my $value = b64_encode Mojo::JSON::encode_json($data), '';
    $value =~ y/=/-/;
}

sub _decode_session_data {
    my $self = shift;
    my $data = shift;

    return if not defined $data;

    $data =~ y/-/=/;
    $data = b64_decode $data;
    $data = Mojo::JSON::j($data);
    return $data;
}

sub _checksum {
    my $self = shift;
    my $value = shift;
    Mojo::Util::hmac_sha1_sum($value, $self->_secret);
}

__PACKAGE__->meta->make_immutable;

1;
