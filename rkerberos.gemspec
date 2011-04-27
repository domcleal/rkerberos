require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'djberg96-krb5-auth'
  spec.version    = '0.9.0'
  spec.author     = 'Daniel Berger'
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'http://github.com/djberg96/krb5-auth'
  spec.platform   = Gem::Platform::RUBY
  spec.summary    = 'A Ruby interface for the the Kerberos library'
  spec.has_rdoc   = true
  spec.test_files = Dir['test/test*']
  spec.extensions = ['ext/krb5_auth/extconf.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') || f.include?('tmp') }
  
  spec.rubyforge_project = 'krb5-auth'
  spec.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST'] + Dir['ext/krb5_auth/*.c']

  spec.add_dependency('rake-compiler')
  
  spec.add_development_dependency('test-unit', '>= 2.0.6')
  spec.add_development_dependency('dbi-dbrc', '>= 1.1.6')
   
  spec.description = <<-EOF
    The krb5-auth library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.

    This particular version was created by Daniel Berger as a fork of
    the krb5-auth project.
  EOF
end
