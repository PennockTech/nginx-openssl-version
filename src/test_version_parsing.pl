#!/usr/bin/env perl
use warnings;
use strict;

my $code_src = 'ngx_openssl_version_module.c';
my $test_out = 'drive_version_parsing.c';
my $test_bin = 'drive_version_parsing';
my @versions = (
	[ "1.1.0a", "0x1010001f" ],
	[ "1.1.0", "0x1010000f" ],
	[ "1.0.1h", "0x1000108f" ],
	[ "1.0.0m", "0x100000df" ],
	[ "0.9.8y", "0x0090819f" ],
	[ "0.9.8za", "0x009081af" ],
	[ "0.9.8zb", "0x009081bf" ], # future prediction
# When we support non-final: 1.0.0n-dev -> 0x100000e0
);

open(SRC, "<", $code_src) or die "open-read($code_src) failed: $!\n";

open(TEST, ">", $test_out) or die "open-write($test_out) failed: $!\n";
while (<DATA>) {
  print TEST $_;
}
while (<SRC>) {
  next unless /START:EXTRACT:parse_openssl_version/../END:EXTRACT:parse_openssl_version/;
  print TEST $_;
}
close(SRC) or die "close-read($code_src) failed, possibly incomplete: $!\n";
close(TEST) or die "close-write($test_out) failed: $!\n";

system("cc -o $test_bin $test_out");

my $FAIL_COUNT = 0;

sub check_version {
	my $in_form = shift;
	my $expect = shift;
	open(CONVERT, '-|', "./$test_bin", $in_form);
	while (<CONVERT>) {
		if (/^\[\d+\]\s+!\s*/) {
			print "NOTICE: $_";
			next;
		}
		next unless /^\[\d+\]\s+"([^"]+)"\s+=\s+(\S+)\s*$/;
		my ($ver_str, $long) = ($1, $2);
		next unless $ver_str eq $in_form;
		if ($long eq $expect) {
			print "ok: $in_form -> $expect\n";
		} else {
			print "FAIL: $in_form SHOULD $expect but got $long\n";
			$FAIL_COUNT++;
		}
		return;
	}
	print "FAIL: no result seen for: $in_form\n";
	$FAIL_COUNT++;
}

foreach my $vp (@versions) {
	check_version $vp->[0], $vp->[1];
}

unlink $test_out, $test_bin;

if ($FAIL_COUNT == 0) {
	print "all tests succeeded\n";
	exit 0;
}
print "TEST FAILURES: $FAIL_COUNT\n";
exit 1;

__END__
// Test suite framework

#include <ctype.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char u_char;

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

static long parse_openssl_version(ngx_str_t *minimum_str, const char **error);

int
main(int argc, char *argv[])
{
  int i;
  ngx_str_t tmp;
  const char *err;
  long version;

  err = NULL;
  for (i = 1; i < argc; ++i) {
    tmp.data = (u_char *)argv[i];
    tmp.len = strlen(argv[i]);
    version = parse_openssl_version(&tmp, &err);
    if (err != NULL) {
      printf("[%d] ! parse error \"%s\": %s\n", i, argv[i], err);
      continue;
    }
    printf("[%d] \"%s\" = %#010lx\n", i, argv[i], version);
  }
}

