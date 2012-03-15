#!/usr/bin/perl -w
##########################################################################
## CkFormLogin 1.0 - Access Management / Form Login Monitor for Nagios
## Copyright 2006-2012, Zetetic LLC
## All rights reserved
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
###########################################################################

use Getopt::Std;
use LWP::UserAgent;
use HTTP::Cookies;
use strict;

# variables for Getopt::Std print_usage
use vars qw ($opt_u $opt_p $opt_a $opt_l $opt_t $opt_d $opt_v);

# Exit codes for nagios
my %status_codes = (
  'UNKWN' => -1,
  'OK'      => 0,
  'WARN'    => 1,
  'CRIT'    => 2,
);

sub print_usage()
{
print<<USAGE;
  CkFormLogin command line:
    ckformlogin.pl -u "<request URL>" -p "<login POST data>" \\
      -a "<login action URL>" \\
      -l "<login page content check value>" \\
      -t "<target page content check value>" \\
      [-v (optional -v parameter to verify target URL after login)]
USAGE
  exit $status_codes{'UNKWN'};
}

sub log_d { log_msg(shift()) if ($opt_d) }
sub log_msg { print shift() . "\n"; }

# Get the options
if (@ARGV < 1)
{
  print_usage();
  exit();
} else {
  #u - URL
  #p - POST content for login page
  #a - Action URL to post login credentials
  #l - Login page content check value
  #t - Target page content check value
  #d - Output debugging information
  #v - verify that target page is the same page initially requested in -u
  getopts('u:p:a:l:t:dv');
  log_d("Target URL: " . $opt_u) if($opt_u);
  log_d("POST Data: " . $opt_p) if($opt_p);
  log_d("Action URL: " . $opt_a) if($opt_a);
  log_d("Login content: " . $opt_l) if($opt_l);
  log_d("Target content: " . $opt_t) if($opt_t);
  log_d("Verify target page redirect? " . $opt_v) if($opt_v);
  log_d("Debug mode? " . $opt_d) if($opt_d);
}

exit &do_check();

sub do_check() {
  my $ua = LWP::UserAgent->new;
  $ua->cookie_jar(HTTP::Cookies->new());
  push @{$ua->requests_redirectable}, ('POST', 'GET');
  $ua->agent("Identicentric CkFormLogin Plugin 1.0");

  my $uri = URI->new($opt_u);
  my $request = HTTP::Request->new(GET => $opt_u);
  log_d("request for protected url: $opt_u");

  my $response = $ua->request($request);
  if ($response->is_success) {
    if(!($response->content =~ /$opt_l/)) {
      log_msg("ERROR: login page content match");
      log_d("DEBUG: login page content causing failure: " . 
        $response->content);
      return $status_codes{CRIT};
    }
  } else {
    log_msg("ERROR: initial request error: ". $response->status_line);
    log_d("DEBUG: request content causing failure: " . $response->content);
    return $status_codes{CRIT};
  }

  log_d("attempting site login...");

  $request = HTTP::Request->new(POST => $opt_a);

  # use x-www-form-urlencoded for HTTP POST. Content is credentials from 
  # nagios configuration
  $request->content_type("application/x-www-form-urlencoded");
  $request->content($opt_p);  

  $response = $ua->request($request);

  if ($response->is_success) {
    if($opt_v and $response->base ne $opt_u) {
      log_msg("ERROR: final redirect to a different page than target:" . 
        $response->base);
      return $status_codes{CRIT};
    }
    if(!($response->content =~ /$opt_t/)) {
      log_msg("ERROR: content match failed on target page");
      log_d("DEBUG: target content: " . $response->content);
      return $status_codes{CRIT};
    }
  } else {
    log_msg("ERROR: request for login resource failed: " . 
      $response->status_line);
    log_d("DEBUG: target content causing failure: " . 
      $response->content);
    return $status_codes{CRIT};
  }

  log_msg("SUCCESS: form login to $opt_u passed");
  return $status_codes{OK};
}

