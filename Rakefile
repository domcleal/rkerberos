require 'rake'
require 'rake/testtask'
require 'rake/extensiontask'
require 'rake/clean'
require 'rbconfig'
include Config

Rake::ExtensionTask.new('rkerberos')

CLEAN.include(
  '**/*.gem',               # Gem files
  '**/*.rbc',               # Rubinius
  '**/*.o',                 # C object file
  '**/*.log',               # Ruby extension build log
  '**/Makefile',            # C Makefile
  '**/conftest.dSYM',       # OS X build directory
  '**/tmp',                 # Temp directory
  "**/*.#{CONFIG['DLEXT']}" # C shared object
)

desc 'Create a tarball of the source'
task :archive do
  spec = eval(IO.read('rkerberos.gemspec'))
  prefix = "rkerberos-#{spec.version}/"
  Dir['*.tar*'].each{ |f| File.delete(f) }
  sh "git archive --prefix=#{prefix} --format=tar HEAD > rkerberos-#{spec.version}.tar"
  sh "gzip rkerberos-#{spec.version}.tar"
end

namespace :gem do
  desc 'Delete any existing gem files in the project.'
  task :clean do
    Dir['*.gem'].each{ |f| File.delete(f) } 
    rm_rf 'lib'
  end 

  desc 'Create the gem'
  task :create => [:clean] do
    spec = eval(IO.read('rkerberos.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc 'Install the gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}" 
  end

  desc 'Create a binary gem'
  task :binary => [:clean, :compile] do
    spec = eval(IO.read('rkerberos.gemspec'))
    spec.platform = Gem::Platform::CURRENT
    spec.extensions = nil
    spec.files = spec.files.reject{ |f| f.include?('ext') }

    Gem::Builder.new(spec).build
  end
end

namespace :sample do
  desc "Run the sample configuration display program"
  task :config => [:compile] do
    sh "ruby -Ilib samples/sample_config_display.rb"
  end
end

namespace 'test' do
  Rake::TestTask.new('all') do |t|
    task :all => [:clean, :compile]
    t.libs << 'ext' 
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('context') do |t|
    task :context => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_context.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('ccache') do |t|
    task :ccache => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_credentials_cache.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('krb5') do |t|
    task :krb5 => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_krb5.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('keytab') do |t|
    task :keytab => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_krb5_keytab.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('keytab_entry') do |t|
    task :keytab_entry => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_keytab_entry.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('principal') do |t|
    task :principal => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_principal.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('kadm5') do |t|
    task :kadm5 => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_kadm5.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('config') do |t|
    task :config => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_config.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('policy') do |t|
    task :policy => [:clean, :compile]
    t.libs << 'ext' 
    t.test_files = FileList['test/test_policy.rb']
    t.warning = true
    t.verbose = true
  end
end

task :default => ['test:all']
task :test => ['test:all']
