require 'mkmf'

dir_config('rkerberos', '/usr/local')

have_header('krb5.h')
have_library('krb5')

if have_header('kadm5/admin.h')
  have_library('kadm5clnt')
else
  raise "kadm5clnt library not found"
end

create_makefile('rkerberos')
