########################################################################
# test_config.rb
#
# Test suite for the Krb5Auth::Kadm5::Config class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Kadm5_Config < Test::Unit::TestCase
  def setup
    @config = Krb5Auth::Kadm5::Config.new
  end

  test "config object is frozen" do
    assert_true(@config.frozen?)
  end

  test "realm basic functionality" do
    assert_respond_to(@config, :realm)
    assert_kind_of(String, @config.realm)
  end

  test "kadmind_port basic functionality" do
    assert_respond_to(@config, :kadmind_port)
    assert_kind_of(Fixnum, @config.kadmind_port)
  end

  test "kpasswd_port basic functionality" do
    assert_respond_to(@config, :kpasswd_port)
    assert_kind_of(Fixnum, @config.kpasswd_port)
  end

  test "admin_server basic functionality" do
    assert_respond_to(@config, :admin_server)
    assert_kind_of(String, @config.admin_server)
  end

  test "admin_keytab basic functionality" do
    assert_respond_to(@config, :admin_keytab)
    assert_kind_of(String, @config.admin_keytab)
  end

  test "acl_file basic functionality" do
    assert_respond_to(@config, :acl_file)
    assert_kind_of(String, @config.acl_file)
  end

  test "dict_file basic functionality" do
    assert_respond_to(@config, :dict_file)
    assert_kind_of([String, NilClass], @config.dict_file)
  end

  test "stash_file basic functionality" do
    assert_respond_to(@config, :stash_file)
    assert_kind_of([String, NilClass], @config.stash_file)
  end

  test "mkey_name basic functionality" do
    assert_respond_to(@config, :mkey_name)
    assert_kind_of([String, NilClass], @config.mkey_name)
  end

  test "mkey_from_kbd basic functionality" do
    assert_respond_to(@config, :mkey_from_kbd)
    assert_kind_of([Fixnum, NilClass], @config.mkey_from_kbd)
  end

  test "enctype basic functionality" do
    assert_respond_to(@config, :enctype)
    assert_kind_of(Fixnum, @config.enctype)
  end

  test "max_life basic functionality" do
    assert_respond_to(@config, :max_life)
    assert_kind_of([Fixnum, NilClass], @config.max_life)
  end

  test "max_rlife basic functionality" do
    assert_respond_to(@config, :max_rlife)
    assert_kind_of([Fixnum, NilClass], @config.max_rlife)
  end

  test "expiration basic functionality" do
    assert_respond_to(@config, :expiration)
    assert_kind_of([Time, NilClass], @config.expiration)
  end

  test "kvno basic functionality" do
    assert_respond_to(@config, :kvno)
    assert_kind_of([Fixnum, NilClass], @config.kvno)
  end

  test "iprop_enabled basic functionality" do
    assert_respond_to(@config, :iprop_enabled)
    assert_boolean(@config.iprop_enabled)
  end

  test "iprop_logfile basic functionality" do
    assert_respond_to(@config, :iprop_logfile)
    assert_kind_of(String, @config.iprop_logfile)
  end

  test "iprop_polltime basic functionality" do
    assert_respond_to(@config, :iprop_poll_time)
    assert_kind_of(Fixnum, @config.iprop_poll_time)
  end

  test "iprop_port basic functionality" do
    assert_respond_to(@config, :iprop_port)
    assert_kind_of([Fixnum, NilClass], @config.iprop_port)
  end

  test "num_keysalts basic functionality" do
    assert_respond_to(@config, :num_keysalts)
    assert_kind_of(Fixnum, @config.num_keysalts)
  end

  test "keysalts basic functionality" do
    assert_respond_to(@config, :keysalts)
    assert_kind_of(Fixnum, @config.keysalts)
  end

  def teardown
    @config = nil
  end
end
