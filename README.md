nginx-openssl-version
=====================

This module causes nginx to write out the runtime version of OpenSSL to the
error log on start-up.  It also adds a directive to the global nginx
configuration, letting you set a minimum version of OpenSSL.


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
    --add-module=$REPO_SRC/github.com/apcera/nginx-openssl-version \
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


License
-------

MIT License, see [LICENSE](LICENSE).
