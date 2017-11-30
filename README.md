# Description
  The rkerberos library provides a Ruby interface for Kerberos.

# Requirements
  Kerberos 1.7.0 or later, including admin header and library files.

# OS X
  Install krb5 using homebrew:

  `brew install krb5`

  then install this gem using the homebrew version of krb5:

  `gem install rkerberos -- --with-rkerberos-dir=/usr/local/opt/krb5`

  or if using bundler:

  `bundle config --global build.rkerberos --with-rkerberos-dir=/usr/local/opt/krb5`
  `bundle install`

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
