require 'mkmf'

dir_config('rkerberos', '/usr/local')

def krb5_config(lib)
  if krb5config = with_config("krb5-config", "krb5-config") and find_executable0(krb5config)
    get ||= proc {|opt, lib|
      opt = xpopen("#{krb5config} --#{opt} #{lib}", err:[:child, :out], &:read)
      Logging.open {puts opt.each_line.map{|s|"=> #{s.inspect}"}}
      opt.strip if $?.success?
    }
  end
  if get and try_ldflags(libs = get['libs', lib])
    cflags = get['cflags', lib]
    if cflags
      $CFLAGS += " " << cflags
      $CXXFLAGS += " " << cflags
    end
    if libs
      $LIBS += " " << libs
    end

    Logging::message "Kerberos configuration for %s\n", lib
    Logging::message "cflags: %s\nlibs: %s\n\n",
                     cflags, libs
    [cflags, libs]
  else
    Logging::message "Kerberos configuration for %s is not found\n", lib
    nil
  end
end


if krb5_config('krb5')
  if krb5_config('kadm-client')
    $CFLAGS << ' -DHAVE_KADM5_ADMIN_H'
  end
  krb5_config('kdb')
else
  have_header('krb5.h')
  have_library('krb5')

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
end

unless pkg_config('com_err')
  puts 'warning: com_err not found, usually a dependency for kadm5clnt'
end

$CFLAGS << ' -std=c99 -Wall -pedantic'
create_makefile('rkerberos')
