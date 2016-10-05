require 'mkmf'

dir_config('rkerberos', '/usr/local')

have_header('krb5.h')
have_library('krb5')

unless pkg_config('com_err')
  puts 'warning: com_err not found, usually a dependency for kadm5clnt'
end

if have_header('kadm5/admin.h')
  have_library('kadm5clnt')
else
  raise "kadm5clnt library not found"
end

if have_header('kdb.h')
  have_library('libkdb5')
else
  raise 'kdb5 library not found'
end

create_makefile('rkerberos')
