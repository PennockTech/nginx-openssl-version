nginx-openssl-version
=====================

This module causes nginx to write out the runtime version of OpenSSL to the
error log on start-up.  It also adds a directive to the global nginx
configuration, letting you set a minimum version of OpenSSL.

(I wrote this at a former employer, Apcera.  It was open sourced, but disappeared without notice around 2019-08-13.  This fork was created before that; to the extent that I wrote all the code, I guess that the canonical upstream repo is now <https://github.com/PennockTech/nginx-openssl-version>.)

Why?
----

Belt & braces.  Build systems break, run-times exhibit unexpected behaviour.
If you want to be _sure_ that you're not running with a vulnerable version of
a library, it can be useful to set that constraint into the configuration
file, so that at run-time you have a final safety-check.

This trades off Availability for Integrity.

Ever run into linker problems where, say, setcap granting of net-bind
privilege on an executable marks it setuid, so `DT_RPATH` in the binary is
ignored in practice, even though `ldd` and invoking the linker with `-list`
claim otherwise, and only using `lsof` to see which file has been mmap'd in
shows what's really happening?  If you're like me, the fact that you can
resolve and fix that isn't enough to let you sleep soundly.  What happens the
next time someone makes a "minor" change?  You might say "statically link",
but what happens when someone temporarily disables that to experiment with
something else, while not being aware of the other consequences?

To _know_ that you have a secure setup, you make sure that there's a
safety-check, instead of relying upon "well we fixed the build process and we
won't break it again because we're just that good".

Thus this module.


Build
-----

Add to nginx build command-line as you would any other module.  The config
file for nginx is in the top-level of this repository.  Thus you might use:

```console
$ cd .../path/to/nginx
$ ./configure \
    --prefix=/where/ever \
    --with-http_ssl_module \
    --add-module=$REPO_SRC/github.com/PennockTech/nginx-openssl-version \
    --with-ld-opt='-L../openssl-1.0.1g -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl' \
    --with-openssl=../openssl-1.0.1g
```

This example assumes that you want a statically-linked nginx using OpenSSL
1.0.1g.


Configuration
-------------

Add to the top-level of your nginx configuration file:

```
openssl_version_minimum 1.0.1g;
```

If you are unlucky, your OS vendor has given you an updated OpenSSL package
which has no identifying information in the embedded version.  In such a
scenario, the best you can work with is the timestamp at which OpenSSL was
built.  This does at least ensure that if you have a fleet of machines which
get the same package, nginx will be protected against machines which missed
the OS package update (but do get the updated nginx binary).

Get the build date:

```console
$ openssl version -b
built on: Mon Apr  7 15:08:30 PDT 2014
```

Then configure at the top-level of your nginx configuration file:

```
openssl_builddate_minimum "Mon Apr  7 15:08:30 PDT 2014";
```

There is no attempt in this code to be flexible in date parsing formats; you
should use the exact output from your known-good version of OpenSSL as the
configuration value.  Because of portability issues around timezone labels,
the timezone portion will be ignored for comparison purposes.  Really, truly,
just copy&paste the output, anything else will fail.

If both minimum options are set, both will be applied -- each must pass.


License
-------

MIT License, see [LICENSE](LICENSE).
