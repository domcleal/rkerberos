########################################################################
# test_krb5.rb
#
# Test suite for the Krb5Auth::Krb5 class. At the moment, this suite
# requires that you export "testuser1" to a local keytab file called
# "test.keytab" in the "test" directory for certain tests to pass.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'open3'
require 'test/unit'
require 'krb5_auth'

class TC_Krb5 < Test::Unit::TestCase
  def self.startup
    @@cache_found = true

    Open3.popen3('klist') do |stdin, stdout, stderr|
      @@cache_found = false unless stderr.gets.nil?
    end

    @@krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    @@realm = IO.read(@@krb5_conf).grep(/default_realm/).first.split('=').last.lstrip.chomp
  end

  def setup
    @krb5    = Krb5Auth::Krb5.new
    @keytab  = Krb5Auth::Krb5::Keytab.new.default_name.split(':').last
    @user    = "testuser1@" + @@realm
    @service = "kadmin/admin"
  end

  test "version constant" do
    assert_equal('0.9.0', Krb5Auth::Krb5::VERSION)
  end

  test "constructor accepts a block and yields itself" do
    assert_nothing_raised{ Krb5Auth::Krb5.new{} }
    Krb5Auth::Krb5.new{ |krb5| assert_kind_of(Krb5Auth::Krb5, krb5) }
  end

  test "get_default_realm basic functionality" do
    assert_respond_to(@krb5, :get_default_realm)
    assert_nothing_raised{ @krb5.get_default_realm }
    assert_kind_of(String, @krb5.get_default_realm)
  end

  test "get_default_realm takes no arguments" do
    assert_raise(ArgumentError){ @krb5.get_default_realm('localhost') }
  end

  test "get_default_realm matches what we found in the krb5.conf file" do
    assert_equal(@@realm, @krb5.get_default_realm)
  end

  test "default_realm is an alias for get_default_realm" do
    assert_alias_method(@krb5, :default_realm, :get_default_realm)
  end

  test "set_default_realm basic functionality" do
    assert_respond_to(@krb5, :set_default_realm)
  end

  test "set_default_realm with no arguments uses the default realm" do
    assert_nothing_raised{ @krb5.set_default_realm }
    assert_equal(@@realm, @krb5.get_default_realm)
  end

  test "set_default_realm with an argument sets the default realm as expected" do
    assert_nothing_raised{ @krb5.set_default_realm('TEST.REALM') }
    assert_equal('TEST.REALM', @krb5.get_default_realm)
  end

  test "argument to set_default_realm must be a string" do
    assert_raise(TypeError){ @krb5.set_default_realm(1) }
  end

  test "set_default_realm accepts a maximum of one argument" do
    assert_raise(ArgumentError){ @krb5.set_default_realm('FOO', 'BAR') }
  end

  test "get_init_creds_password basic functionality" do
    assert_respond_to(@krb5, :get_init_creds_password)
  end

  test "get_init_creds_password requires two arguments" do
    assert_raise(ArgumentError){ @krb5.get_init_creds_password }
    assert_raise(ArgumentError){ @krb5.get_init_creds_password('test') }
  end

  test "get_init_creds_password requires string arguments" do
    assert_raise(TypeError){ @krb5.get_init_creds_password(1, 2) }
    assert_raise(TypeError){ @krb5.get_init_creds_password('test', 1) }
  end

  test "calling get_init_creds_password after closing the object raises an error" do
    @krb5.close
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.get_init_creds_password('foo', 'xxx') }
  end

  test "calling get_init_creds_password after closing the object raises a specific error message" do
    @krb5.close
    assert_raise_message('no context has been established'){ @krb5.get_init_creds_password('foo', 'xxx') }
  end

  test "get_init_creds_keytab basic functionality" do
    assert_respond_to(@krb5, :get_init_creds_keytab)
  end

  test "get_init_creds_keytab uses a default keytab if no keytab file is specified" do
    omit_unless(File.exists?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user) }
  end

  test "get_init_creds_keytab accepts a keytab" do
    omit_unless(File.exists?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab) }
  end

  # This test will probably fail (since it defaults to "host") so I've commented it out for now.
  #test "get_init_creds_keytab uses default service principal if no arguments are provided" do
  #  omit_unless(File.exists?(@keytab), "keytab file not found, skipping")
  #  assert_nothing_raised{ @krb5.get_init_creds_keytab }
  #end

  test "get_init_creds_keytab accepts a service name" do
    omit_unless(File.exists?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab, @service) }
  end

  test "get_init_creds_keytab requires string arguments" do
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(1) }
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(@user, 1) }
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(@user, @keytab, 1) }
  end

  test "calling get_init_creds_keytab after closing the object raises an error" do
    @krb5.close
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.get_init_creds_keytab(@user, @keytab) }
  end

  test "change_password basic functionality" do
    assert_respond_to(@krb5, :change_password)
  end

  test "change_password requires two arguments" do
    assert_raise(ArgumentError){ @krb5.change_password }
    assert_raise(ArgumentError){ @krb5.change_password('XXXXXXXX') }
  end

  test "change_password requires two strings" do
    assert_raise(TypeError){ @krb5.change_password(1, 'XXXXXXXX') }
    assert_raise(TypeError){ @krb5.change_password('XXXXXXXX', 1) }
  end

  test "change_password fails if there is no context or principal" do
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.change_password("XXX", "YYY") }
    assert_raise_message('no principal has been established'){ @krb5.change_password("XXX", "YYY") }
  end

  test "get_default_principal basic functionality" do
    assert_respond_to(@krb5, :get_default_principal)
  end

  test "get_default_principal returns a string if cache found" do
    omit_unless(@@cache_found, "No credentials cache found, skipping")
    assert_nothing_raised{ @krb5.get_default_principal }
    assert_kind_of(String, @krb5.get_default_principal)
  end

  test "get_default_principal raises an error if no cache is found" do
    omit_if(@@cache_found, "Credential cache found, skipping")
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.get_default_principal }
  end

  test "get_permitted_enctypes basic functionality" do
    assert_respond_to(@krb5, :get_permitted_enctypes)
    assert_nothing_raised{ @krb5.get_permitted_enctypes }
    assert_kind_of(Hash, @krb5.get_permitted_enctypes)
  end

  test "get_permitted_enctypes returns expected results" do
    hash = @krb5.get_permitted_enctypes
    assert_kind_of(Fixnum, hash.keys.first)
    assert_kind_of(String, hash.values.first)
    assert_true(hash.values.first.size > 0)
  end

  def teardown
    @krb5.close
    @krb5 = nil
  end

  def self.shutdown
    @@cache_found = nil
  end
end
