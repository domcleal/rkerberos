########################################################################
# test_kadm5.rb
#
# Tests for the Krb5Auth::Kadm5 class.
#
# This test suite requires that you have an entry in your .dbrc file
# for 'local-kerberos' which includes an admin principal, password and
# optional $KRB5_CONFIG file.
#
# Some keytab tests will fail if your local-kerberos entry is not
# also in the keytab file.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'dbi/dbrc'
require 'krb5_auth'
require 'socket'

class TC_Krb5Auth_Kadm5 < Test::Unit::TestCase
  def self.startup
    @@server = Krb5Auth::Kadm5::Config.new.admin_server
    @@info = DBI::DBRC.new('local-kerberos')
    @@host = Socket.gethostname

    # For local testing the FQDN may or may not be available, so let's assume
    # that hosts with the same name are on the same domain.
    if @@server.include?('.') && !@@host.include?('.')
      @@server = @@server.split('.').first
    end

    ENV['KRB5_CONFIG'] = @@info.driver || ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
  end

  def setup
    @user = @@info.user
    @pass = @@info.passwd
    @kadm = nil
    @princ = nil
    @policy = nil
    @test_princ = "zztop"
    @test_policy = "test_policy"

    @keytab = Krb5Auth::Krb5::Keytab.new.default_name.split(':').last

    unless File.exists?(@keytab)
      @keytab = '/etc/krb5.keytab'
    end
  end

  test "constructor basic functionality" do
    assert_respond_to(Krb5Auth::Kadm5, :new)
  end

  test "constructor with valid user and password works as expected" do
    assert_nothing_raised{
      @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    }
  end

  test "constructor with valid service works as expected" do
    assert_nothing_raised{
      @kadm = Krb5Auth::Kadm5.new(
        :principal => @user,
        :password  => @pass,
        :service   => "kadmin/admin"
      )
    }
  end

  test "constructor with valid user and default keytab works as expected" do
    omit_unless(@@host == @@server, "keytab on different host, skipping")
    omit_unless(File.exists?(@keytab), "default keytab file '#{@keytab}' not found")

    assert_nothing_raised{
      @kadm = Krb5Auth::Kadm5.new(:principal => @user, :keytab => true)
    }
  end

  test "constructor with valid user and explicit keytab works as expected" do
    omit_unless(@@host == @@server, "keytab on different host, skipping")
    omit_unless(File.exists?(@keytab), "keytab file '#{@keytab}' not found")

    assert_nothing_raised{
      @kadm = Krb5Auth::Kadm5.new(:principal => @user, :keytab => @keytab)
    }
  end

  test "constructor only accepts a hash argument" do
    assert_raise(TypeError){ Krb5Auth::Kadm5.new(@user) }
    assert_raise(TypeError){ Krb5Auth::Kadm5.new(1) }
  end

  test "constructor accepts a block and yields itself" do
    assert_nothing_raised{ Krb5Auth::Kadm5.new(:principal => @user, :password => @pass){} }
    Krb5Auth::Kadm5.new(:principal => @user, :password => @pass){ |kadm5|
      assert_kind_of(Krb5Auth::Kadm5, kadm5)
    }
  end

  test "principal must be specified" do
    assert_raise(ArgumentError){ Krb5Auth::Kadm5.new({}) }
    assert_raise_message("principal must be specified"){ Krb5Auth::Kadm5.new({}) }
  end

  test "principal value must be a string" do
    assert_raise(TypeError){ Krb5Auth::Kadm5.new(:principal => 1) }
  end

  test "password value must be a string" do
    assert_raise(TypeError){ Krb5Auth::Kadm5.new(:principal => @user, :password => 1) }
  end

  test "keytab value must be a string or a boolean" do
    assert_raise(TypeError){ Krb5Auth::Kadm5.new(:principal => @user, :keytab => 1) }
  end

  test "service value must be a string" do
    assert_raise(TypeError){
      Krb5Auth::Kadm5.new(:principal => @user, :password => @pass, :service => 1)
    }
  end

  test "an error is raised if an invalid service name is used" do
    assert_raise(Krb5Auth::Kadm5::Exception){
      Krb5Auth::Kadm5.new(:principal => @user, :password => @pass, :service => 'bogus')
    }
  end

  test "an error is raised if both a keytab and a password are provided" do
    assert_raise(ArgumentError){
      Krb5Auth::Kadm5.new(:principal => @user, :keytab => true, :password => "xxx")
    }
    assert_raise_message("cannot use both a password and a keytab"){
      Krb5Auth::Kadm5.new(:principal => @user, :keytab => true, :password => "xxx")
    }
  end

  test "constructor with invalid user or password raises an error" do
    assert_raise(Krb5Auth::Kadm5::Exception){
      Krb5Auth::Kadm5.new(:principal => @user, :password => 'bogus')
    }
    assert_raise(Krb5Auth::Kadm5::Exception){
      Krb5Auth::Kadm5.new(:principal => 'bogus', :password => @pass)
    }
  end

  test "constructor with invalid user or password raises a specific error message" do
    assert_raise_message('kadm5_init_with_password: Incorrect password'){
      Krb5Auth::Kadm5.new(:principal => @user, :password => 'bogus')
    }
    assert_raise_message('kadm5_init_with_password: Client not found in Kerberos database'){
      Krb5Auth::Kadm5.new(:principal => 'bogus', :password => @pass)
    }
  end

  test "set_password basic functionality" do
    @kadm5 = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm5, :set_password)
  end

  test "set_password requires two arguments" do
    @kadm5 = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm5.set_password }
    assert_raise(ArgumentError){ @kadm5.set_password('user') }
    assert_raise(ArgumentError){ @kadm5.set_password('user', 'xxx', 'yyy') }
  end

  test "set_password requires string arguments" do
    @kadm5 = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(TypeError){ @kadm5.set_password('user',2) }
    assert_raise(TypeError){ @kadm5.set_password(1, 'xxxx') }
  end

  test "attempting to set the password for an invalid user raises an error" do
    @kadm5 = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm5.set_password('bogususer', 'xxxyyy') }
  end

  ### Policy

  test "create_policy basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :create_policy)
  end

  test "create_policy accepts a Policy object" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    policy = Krb5Auth::Kadm5::Policy.new(hash)
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(policy) }
  end

  test "create_policy accepts a hash" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(hash) }
  end

  test "policy can be found after creation" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_policy(hash)
    assert_nothing_raised{ @kadm.get_policy(@test_policy) }
  end

  test "create_policy only accepts one argument" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.create_policy(hash, hash) }
  end

  test "attempting to create a policy that already exists raises an error" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_nothing_raised{ @kadm.create_policy(hash) }
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.create_policy(hash) }
  end

  test "delete_policy basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :delete_policy)
  end

  test "delete_policy works as expected" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_nothing_raised{ @kadm.create_policy(:name => @test_policy) }
    assert_nothing_raised{ @kadm.delete_policy(@test_policy) }
  end

  test "delete_policy takes one argument and only one argument" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.delete_policy }
    assert_raise(ArgumentError){ @kadm.delete_policy(@test_policy, @test_policy) }
  end

  ### Principal

  test "create_principal basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :create_principal)
  end

  test "create_principal creates a user as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
  end

  test "create_principal requires two arguments" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.create_principal }
    assert_raise(ArgumentError){ @kadm.create_principal(@user) }
    assert_raise(ArgumentError){ @kadm.create_principal(@user, @pass, @pass) }
  end

  test "attempting to create a principal that already exists raises an error" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.create_principal(@test_princ, "changeme") }
  end

  test "delete_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :delete_principal)
  end

  test "delete_principal works as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @kadm.delete_principal(@test_princ) }
  end

  test "delete_principal takes one argument and only one argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.delete_principal }
    assert_raise(ArgumentError){ @kadm.delete_principal(@user, @pass) }
  end

  test "find_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :find_principal)
  end

  test "find_principal returns a Struct::Principal object if found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @princ = @kadm.find_principal(@test_princ) }
    assert_kind_of(Krb5Auth::Krb5::Principal, @princ)
  end

  test "find_principal returns nil if not found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nil(@kadm.find_principal('bogus'))
  end

  test "find_principal requires a string argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(TypeError){ @kadm.find_principal(1) }
  end

  test "find_principal requires one and only one argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.find_principal }
    assert_raise(ArgumentError){ @kadm.find_principal(@user, @user) }
  end

  test "generate_random_key basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    assert_respond_to(@kadm, :generate_random_key)
    assert_nothing_raised{ @kadm.generate_random_key(@test_princ) }
  end

  test "generate_random_key returns the number of keys generated" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    assert_kind_of(Fixnum, @kadm.generate_random_key(@test_princ))
    assert_true(@kadm.generate_random_key(@test_princ) > 0)
  end

  test "generate_random_key requires one argument" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.generate_random_key }
    assert_raise(ArgumentError){ @kadm.generate_random_key(@test_princ, @test_princ) }
  end

  test "generate_random_key requires a string argument" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(TypeError){ @kadm.generate_random_key(7) }
  end

  test "generate_random_key raises an error if the principal cannot be found" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.generate_random_key('bogus') }
  end

  test "get_policy basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :get_policy)
  end

  test "get_policy returns a Policy object if found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(:name => @test_policy, :min_length => 5) }
    assert_nothing_raised{ @policy = @kadm.get_policy(@test_policy) }
    assert_kind_of(Krb5Auth::Kadm5::Policy, @policy)
  end

  test "get_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :get_principal)
  end

  test "get_principal returns a Struct::Principal object if found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @princ = @kadm.get_principal(@test_princ) }
    assert_kind_of(Krb5Auth::Krb5::Principal, @princ)
  end

  test "get_principal raises an error if not found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(Krb5Auth::Kadm5::PrincipalNotFoundException){ @kadm.get_principal('bogus') }
  end

  test "get_principal requires a string argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(TypeError){ @kadm.get_principal(1) }
  end

  test "get_principal requires one and only one argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.get_principal }
    assert_raise(ArgumentError){ @kadm.get_principal(@user, @user) }
  end

  test "close basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :close)
    assert_nothing_raised{ @kadm.close }
  end

  test "calling close multiple times is a no-op" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
  end

  test "close does not accept any arguments" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.close(1) }
  end

  test "calling close on an already closed object raises an error" do
    @kadm = Krb5Auth::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    @kadm.close

    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.get_principal(@test_princ) }
    assert_raise_message('no context has been established'){ @kadm.get_principal(@test_princ) }
  end

  def teardown
    if @kadm
      @kadm.delete_principal(@test_princ) rescue nil
      @kadm.delete_policy(@test_policy) rescue nil
      @kadm.close
    end

    @user   = nil
    @pass   = nil
    @kadm   = nil
    @princ  = nil
    @policy = nil
  end

  def self.shutdown
    @@host = nil
    @@info = nil
    @@server = nil
  end
end
