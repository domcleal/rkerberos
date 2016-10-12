########################################################################
# test_kadm5.rb
#
# Tests for the Kerberos::Kadm5 class.
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
require 'rkerberos'
require 'socket'

class TC_Kerberos_Kadm5 < Test::Unit::TestCase
  def self.startup
    @@server = Kerberos::Kadm5::Config.new.admin_server
    @@info = DBI::DBRC.new('local-kerberos')
    @@host = Socket.gethostname
    begin
      @@ldap_info = DBI::DBRC.new('kerberos-ldap')
    rescue DBI::DBRC::DBError
      @@ldap_info = nil
    end

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

    if @@ldap_info
      gem 'net-ldap'
      require 'net/ldap'

      username = @@ldap_info.user.split('@')
      @bind_dn = username[0]
      @ldap_host = username[1]
      @ldap_password = @@ldap_info.password
      driver = @@ldap_info.driver.split(':')
      @subtree_dn = driver[0]
      @existing_ldap = driver[1]
      @userprefix = driver[2]
      @ldap_test_princ = 'martymcfly'

      @ldap = Net::LDAP.new(host: @ldap_host)
      @ldap.authenticate(@bind_dn, @ldap_password)
    end
    @keytab = Kerberos::Krb5::Keytab.new.default_name.split(':').last

    unless File.exist?(@keytab)
      @keytab = '/etc/krb5.keytab'
    end
  end

  test "constructor basic functionality" do
    assert_respond_to(Kerberos::Kadm5, :new)
  end

  test "constructor with valid user and password works as expected" do
    assert_nothing_raised{
      @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    }
  end

  test "constructor with valid service works as expected" do
    assert_nothing_raised{
      @kadm = Kerberos::Kadm5.new(
        :principal => @user,
        :password  => @pass,
        :service   => "kadmin/admin"
      )
    }
  end

  test "constructor with valid user and default keytab works as expected" do
    omit_unless(@@host == @@server, "keytab on different host, skipping")
    omit_unless(File.exist?(@keytab), "default keytab file '#{@keytab}' not found")

    assert_nothing_raised{
      @kadm = Kerberos::Kadm5.new(:principal => @user, :keytab => true)
    }
  end

  test "constructor with valid user and explicit keytab works as expected" do
    omit_unless(@@host == @@server, "keytab on different host, skipping")
    omit_unless(File.exist?(@keytab), "keytab file '#{@keytab}' not found")

    assert_nothing_raised{
      @kadm = Kerberos::Kadm5.new(:principal => @user, :keytab => @keytab)
    }
  end

  test "constructor only accepts a hash argument" do
    assert_raise(TypeError){ Kerberos::Kadm5.new(@user) }
    assert_raise(TypeError){ Kerberos::Kadm5.new(1) }
  end

  test "constructor accepts a block and yields itself" do
    assert_nothing_raised{ Kerberos::Kadm5.new(:principal => @user, :password => @pass){} }
    Kerberos::Kadm5.new(:principal => @user, :password => @pass){ |kadm5|
      assert_kind_of(Kerberos::Kadm5, kadm5)
    }
  end

  test "principal must be specified" do
    assert_raise(ArgumentError){ Kerberos::Kadm5.new({}) }
    assert_raise_message("principal must be specified"){ Kerberos::Kadm5.new({}) }
  end

  test "principal value must be a string" do
    assert_raise(TypeError){ Kerberos::Kadm5.new(:principal => 1) }
  end

  test "password value must be a string" do
    assert_raise(TypeError){ Kerberos::Kadm5.new(:principal => @user, :password => 1) }
  end

  test "keytab value must be a string or a boolean" do
    assert_raise(TypeError){ Kerberos::Kadm5.new(:principal => @user, :keytab => 1) }
  end

  test "service value must be a string" do
    assert_raise(TypeError){
      Kerberos::Kadm5.new(:principal => @user, :password => @pass, :service => 1)
    }
  end

  test "an error is raised if an invalid service name is used" do
    assert_raise(Kerberos::Kadm5::Exception){
      Kerberos::Kadm5.new(:principal => @user, :password => @pass, :service => 'bogus')
    }
  end

  test "an error is raised if both a keytab and a password are provided" do
    assert_raise(ArgumentError){
      Kerberos::Kadm5.new(:principal => @user, :keytab => true, :password => "xxx")
    }
    assert_raise_message("cannot use both a password and a keytab"){
      Kerberos::Kadm5.new(:principal => @user, :keytab => true, :password => "xxx")
    }
  end

  test "constructor with invalid user or password raises an error" do
    assert_raise(Kerberos::Kadm5::Exception){
      Kerberos::Kadm5.new(:principal => @user, :password => 'bogus')
    }
    assert_raise(Kerberos::Kadm5::Exception){
      Kerberos::Kadm5.new(:principal => 'bogus', :password => @pass)
    }
  end

  test "constructor with invalid user or password raises a specific error message" do
    assert_raise_message('kadm5_init_with_password: Incorrect password'){
      Kerberos::Kadm5.new(:principal => @user, :password => 'bogus')
    }
    assert_raise_message('kadm5_init_with_password: Client not found in Kerberos database'){
      Kerberos::Kadm5.new(:principal => 'bogus', :password => @pass)
    }
  end

  test "set_password basic functionality" do
    @kadm5 = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm5, :set_password)
  end

  test "set_password requires two arguments" do
    @kadm5 = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm5.set_password }
    assert_raise(ArgumentError){ @kadm5.set_password('user') }
    assert_raise(ArgumentError){ @kadm5.set_password('user', 'xxx', 'yyy') }
  end

  test "set_password requires string arguments" do
    @kadm5 = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(TypeError){ @kadm5.set_password('user',2) }
    assert_raise(TypeError){ @kadm5.set_password(1, 'xxxx') }
  end

  test "attempting to set the password for an invalid user raises an error" do
    @kadm5 = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(Kerberos::Kadm5::Exception){ @kadm5.set_password('bogususer', 'xxxyyy') }
  end

  ### Policy

  test "create_policy basic functionality" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :create_policy)
  end

  test "create_policy accepts a Policy object" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    policy = Kerberos::Kadm5::Policy.new(hash)
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(policy) }
  end

  test "create_policy accepts a hash" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(hash) }
  end

  test "policy can be found after creation" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_policy(hash)
    assert_nothing_raised{ @kadm.get_policy(@test_policy) }
  end

  test "create_policy only accepts one argument" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.create_policy(hash, hash) }
  end

  test "attempting to create a policy that already exists raises an error" do
    hash = {:name => @test_policy, :min_length => 5, :max_life => 10000, :min_classes => 2}
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_nothing_raised{ @kadm.create_policy(hash) }
    assert_raise(Kerberos::Kadm5::Exception){ @kadm.create_policy(hash) }
  end

  test "delete_policy basic functionality" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :delete_policy)
  end

  test "delete_policy works as expected" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_nothing_raised{ @kadm.create_policy(:name => @test_policy) }
    assert_nothing_raised{ @kadm.delete_policy(@test_policy) }
  end

  test "delete_policy takes one argument and only one argument" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.delete_policy }
    assert_raise(ArgumentError){ @kadm.delete_policy(@test_policy, @test_policy) }
  end

  ### Principal

  test "create_principal basic functionality" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_respond_to(@kadm, :create_principal)
  end

  test "create_principal creates a user as expected" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
  end

  ##
  # The following two tests are skipped if there is no .dbrc entry for 'kerberos-ldap'
  # The expected format for the entries is as follows
  #   username: <bind_dn>@<ldap.hostname>
  #   password: <ldap_bind_password>
  #   driver: <krbSubtreeDn>:<user>:<userprefix>
  # Username must be an LDAP user that has access to read attributes of objects under krbSubtreeDn,
  # so possibly an administrative user.
  # Password must be the LDAP bind password for that user
  # krbSubtreeDn must be configured in kerberos as a subtree that contains kerberos principals
  # user must be an existing ldap user that does not yet have kerberos information attached to them
  # user must be accessible in LDAP as <userprefix>=<user>,<krbSubtreeDn>, so if userprefix is uid,
  # user is foobar, and krbSubtreeDn is ou=People,dc=example,dc=com, the driver variable should read
  # ou=People,dc=example.com:foobar:uid
  # The user in the driver must not be the same as the user that is used to connect to kerberos, as it 
  # is deleted after each test.
  # If the entry is present, but the format is not matched (or LDAP is misconfigured), theses tests fail.
  ##
  test "create_principal with db_princ_args creates a user under the expected subtree" do
    omit_unless(@@ldap_info, "No LDAP info specified, skipping db_args tests")
    assert_nothing_raised { @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised { @kadm.create_principal(@ldap_test_princ, "changeme", "containerdn=#{@subtree_dn}") }
    @ldap.open do |ldap|
      filter = Net::LDAP::Filter.eq(:krbPrincipalName, "#{@ldap_test_princ}@*")
      base = @subtree_dn
      assert_not_empty(ldap.search(:base => base, :filter => filter, :return_result => true))
    end
  end

  test "create_principal with a dn db_princ_args correctly adds kerberos information to existing user" do
    omit_unless(@@ldap_info, "No LDAP info specified, skipping db_princ_args tests")
    assert_nothing_raised { @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised { @kadm.create_principal(@existing_ldap, "changeme", "dn=#{@userprefix}=#{@existing_ldap},#{@subtree_dn}") }
    @ldap.open do |ldap|
      filter = Net::LDAP::Filter.eq(:uid, @existing_ldap) & Net::LDAP::Filter.eq(:objectclass, 'krbPrincipalAux')
      base = @subtree_dn
      assert_not_empty(ldap.search(:base => base, :filter => filter, :return_result => true))
    end
  end

  test "create_principal requires two or three arguments" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.create_principal }
    assert_raise(ArgumentError){ @kadm.create_principal(@user) }
    assert_raise(ArgumentError){ @kadm.create_principal(@user, @pass, @pass, @pass) }
  end

  test "attempting to create a principal that already exists raises an error" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_raise(Kerberos::Kadm5::Exception){ @kadm.create_principal(@test_princ, "changeme") }
  end

  test "delete_principal basic functionality" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :delete_principal)
  end

  test "delete_principal works as expected" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @kadm.delete_principal(@test_princ) }
  end

  test "delete_principal takes one argument and only one argument" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.delete_principal }
    assert_raise(ArgumentError){ @kadm.delete_principal(@user, @pass) }
  end

  test "find_principal basic functionality" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :find_principal)
  end

  test "find_principal returns a Struct::Principal object if found" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @princ = @kadm.find_principal(@test_princ) }
    assert_kind_of(Kerberos::Krb5::Principal, @princ)
  end

  test "find_principal returns nil if not found" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nil(@kadm.find_principal('bogus'))
  end

  test "find_principal requires a string argument" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(TypeError){ @kadm.find_principal(1) }
  end

  test "find_principal requires one and only one argument" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.find_principal }
    assert_raise(ArgumentError){ @kadm.find_principal(@user, @user) }
  end

  test "generate_random_key basic functionality" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    assert_respond_to(@kadm, :generate_random_key)
    assert_nothing_raised{ @kadm.generate_random_key(@test_princ) }
  end

  test "generate_random_key returns the number of keys generated" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    assert_kind_of(Fixnum, @kadm.generate_random_key(@test_princ))
    assert_true(@kadm.generate_random_key(@test_princ) > 0)
  end

  test "generate_random_key requires one argument" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.generate_random_key }
    assert_raise(ArgumentError){ @kadm.generate_random_key(@test_princ, @test_princ) }
  end

  test "generate_random_key requires a string argument" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(TypeError){ @kadm.generate_random_key(7) }
  end

  test "generate_random_key raises an error if the principal cannot be found" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(Kerberos::Kadm5::Exception){ @kadm.generate_random_key('bogus') }
  end

  test "get_policy basic functionality" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :get_policy)
  end

  test "get_policy returns a Policy object if found" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_policy(:name => @test_policy, :min_length => 5) }
    assert_nothing_raised{ @policy = @kadm.get_policy(@test_policy) }
    assert_kind_of(Kerberos::Kadm5::Policy, @policy)
  end

  test "get_principal basic functionality" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :get_principal)
  end

  test "get_principal returns a Struct::Principal object if found" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @princ = @kadm.get_principal(@test_princ) }
    assert_kind_of(Kerberos::Krb5::Principal, @princ)
  end

  test "get_principal raises an error if not found" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(Kerberos::Kadm5::PrincipalNotFoundException){ @kadm.get_principal('bogus') }
  end

  test "get_principal requires a string argument" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(TypeError){ @kadm.get_principal(1) }
  end

  test "get_principal requires one and only one argument" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_raise(ArgumentError){ @kadm.get_principal }
    assert_raise(ArgumentError){ @kadm.get_principal(@user, @user) }
  end

  test "close basic functionality" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_respond_to(@kadm, :close)
    assert_nothing_raised{ @kadm.close }
  end

  test "calling close multiple times is a no-op" do
    assert_nothing_raised{ @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass) }
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
  end

  test "close does not accept any arguments" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    assert_raise(ArgumentError){ @kadm.close(1) }
  end

  test "calling close on an already closed object raises an error" do
    @kadm = Kerberos::Kadm5.new(:principal => @user, :password => @pass)
    @kadm.create_principal(@test_princ, "changeme")
    @kadm.close

    assert_raise(Kerberos::Kadm5::Exception){ @kadm.get_principal(@test_princ) }
    assert_raise_message('no context has been established'){ @kadm.get_principal(@test_princ) }
  end

  def teardown
    if @kadm
      @kadm.delete_principal(@test_princ) rescue nil
      @kadm.delete_policy(@test_policy) rescue nil
      if @@ldap_info
        @kadm.delete_principal(@ldap_test_princ) rescue nil
        @kadm.delete_principal(@existing_ldap) rescue nil
      end
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
