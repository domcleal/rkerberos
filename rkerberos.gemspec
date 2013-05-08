require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'rkerberos'
  spec.version    = '0.1.1'
  spec.authors    = ['Daniel Berger', 'Dominic Cleal']
  spec.license    = 'Artistic 2.0'
  spec.email      = ['djberg96@gmail.com', 'dcleal@redhat.com']
  spec.homepage   = 'http://github.com/domcleal/rkerberos'
  spec.summary    = 'A Ruby interface for the the Kerberos library'
  spec.test_files = Dir['test/test*']
  spec.extensions = ['ext/rkerberos/extconf.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') || f.include?('tmp') }
  
  spec.extra_rdoc_files  = ['README.md', 'CHANGES', 'MANIFEST'] + Dir['ext/rkerberos/*.c']

  spec.add_dependency('rake-compiler')
  
  spec.add_development_dependency('test-unit', '>= 2.1.0')
  spec.add_development_dependency('dbi-dbrc', '>= 1.1.6')
   
  spec.description = <<-EOF
    The rkerberos library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.
  EOF
end
