# Description
  The rkerberos library provides a Ruby interface for Kerberos.

# Requirements
  Kerberos 1.7.0 or later, including admin header and library files.

# OS X (10.11)
  krb5 must be installed from source before installing the rkerberos gem:
```
  brew install openssl
  curl -0 http://web.mit.edu/kerberos/dist/krb5/1.14/krb5-1.14.tar.gz
  tar -xzf krb5-1.14.tar.gz
  cd krb5-1.14/src
  export CPPFLAGS='-I/usr/local/opt/openssl/include'
  export LDFLAGS='-L/usr/local/opt/openssl/lib'
  ./configure
  make
  make install
```
  latest release is here: http://web.mit.edu/kerberos/dist/index.html

# Synopsis
```ruby
  require 'rkerberos'

  # Get the default realm name
  krb5 = Kerberos::Krb5.new
  puts krb5.default_realm
  krb5.close

  # Get the default keytab name
  keytab = Kerberos::Krb5::Keytab.new
  puts keytab.default_name
  keytab.close

  # Set the password for a given principal
  kadm5 = Kerberos::Kadm5.new(:principal => 'foo/admin', :password => 'xxxx')
  kadm5.set_password('someuser', 'abc123')
  kadm5.close

  # Using the block form
  Kerberos::Kadm5.new(:principal => 'foo/admin', :password => 'xxxx') do |kadm5|
    p kadm5.get_principal('someuser')
    kadm5.set_password('someuser', 'abc123')
  end
```

# Notes
  The rkerberos library is a repackaging of my custom branch of the krb5_auth
  library. Eventually the gem djberg96-krb5_auth will be removed from the gem
  index.

# MIT vs Heimdal
  This code was written for the MIT Kerberos library. It has not been tested
  with the Heimdal Kerberos library.

# TODO
* Create a separate class for the replay cache.
* Better credentials cache support.
* Ability to add and delete keytab entries.

# Authors
* Daniel Berger
* Dominic Cleal (maintainer)
* Simon Levermann (maintainer)

# License
  rkerberos is distributed under the Artistic 2.0 license.
