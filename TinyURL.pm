# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

# Author:  Giovanni Bechis <gbechis@apache.org>

=head1 NAME

TinyURL - checks URLs redirectors

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::TinyURL

  url_redirector 2.gp
  url_redirector 7.ly
  ...

=head1 DESCRIPTION

This plugin checks URLs redirectors aka shorteners, do an HTTP HEAD request
and retrieve the final URL destination, it finally adds this URL to the list
of URIs checked by SpamAssassin.

=cut

package Mail::SpamAssassin::Plugin::TinyURL;

use strict;
use warnings;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; };

BEGIN
{
    eval{
      import  LWP::UserAgent
    };
}

use vars qw(@ISA);
our @ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 0.1;

sub dbg { Mail::SpamAssassin::Plugin::dbg ("TinyURL: @_"); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  if(!HAS_LWP_USERAGENT) {
    warn("Lwp::UserAgent dependency not installed");
    return;
  } else {
    # XXX remove hardcoded values
    $self->{ua} = new LWP::UserAgent;
    $self->{ua}->{max_redirect} = 0;
    $self->{ua}->{timeout} = 5;
    $self->{ua}->env_proxy;
  }

  $self->set_config($mailsaobject->{conf});
  $self->register_method_priority ('parsed_metadata', -1);
  $self->register_eval_rule('tiny_url_check',  $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

=head1 ADMINISTRATOR SETTINGS

=over 4

=item url_redirector [...]

A list of url redirectors must be setup to look at different url shorteners.

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'url_redirector',
    is_admin => 1,
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $dom (split(/\s+/, $value)) {
        $self->{url_redirector}->{$dom} = 1;
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $msg = $opts->{msg};
  my $count = 0;

  return if (!$pms->is_dns_available() || !HAS_LWP_USERAGENT);

  $self->{url_redirector} = $pms->{main}->{conf}->{url_redirector};

  return if not defined $self->{url_redirector};

  my %tiny_urls;
  my $uris = $pms->get_uri_detail_list();
  while (my($uri, $info) = each %{$uris}) {
    if(not defined $info->{domains}) {
      next;
    }
    foreach my $dom ( keys %{ $info->{domains} } ) {
      dbg("Checking domain $dom");
      if (exists $self->{url_redirector}->{$dom}) {
        $tiny_urls{$uri} = 1;
	$count++;
      }
    }
  }

  return unless $count gt 0;

  my $url_count = 0;
  foreach my $turl (keys %tiny_urls) {
    # XXX remove hardcoded value
    next if ($url_count gt 5);
    my $dest = $self->_check_tiny($pms, $turl);
    $url_count++;
  }

}

sub _check_tiny {
  my ($self, $pms, $tiny_url, %found) = @_;

  my ($dest, $dom, $redir_dom);

  my $resp = $self->{ua}->head($tiny_url);

  if ($resp->is_redirect) {
      $dest = $resp->headers->{location};
      $dom = $self->{main}->{registryboundaries}->uri_to_domain($dest);
      $redir_dom = $self->{main}->{registryboundaries}->uri_to_domain($tiny_url);

      next if ($dom eq $redir_dom);

      if (exists $self->{url_redirector}->{$redir_dom}) {
        if($resp->{_rc} == '301') {
	  push(@{ $pms->{tiny_url} }, $dom);
          dbg("HIT! $dom found in redirector $tiny_url");
          $pms->test_log("$tiny_url ($dom)");
    	  $pms->add_uri_detail_list($dest);
        }
      }
      return;
  }
  return $dom;
}

sub tiny_url_check {
  my ($self, $pms) = @_;

  my $rulename = $pms->get_current_eval_rule_name();
  foreach my $hit ( @{ $pms->{tiny_url} } ) {
    $pms->got_hit($rulename, "", ruletype => 'eval');
  }
  return;
}

1;
