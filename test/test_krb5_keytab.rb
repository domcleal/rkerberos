########################################################################
# test_krb5_keytab.rb
#
# Test suite for the Krb5Auth::Krb5::Keytab class.
#
# At the moment this test suite assumes that there are two or more
# principals in the keytab. Temporary keytab creation is handled using
# pty + expect.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'tmpdir'
require 'fileutils'
require 'test/unit'
require 'krb5_auth'
require 'pty'
require 'expect'

class TC_Krb5_Keytab < Test::Unit::TestCase
  def self.startup
    file = Dir.tmpdir + "/test.keytab"

    PTY.spawn('kadmin.local') do |reader, writer, pid|
      reader.gets
      reader.expect(/local:\s+/)

      writer.puts("ktadd -k #{file} testuser1")
      reader.expect(/local:\s+/)

      writer.puts("ktadd -k #{file} testuser2")
      reader.expect(/local:\s+/)
    end

    @@key_file = "FILE:" + file
    @@home_dir = ENV['HOME'] || ENV['USER_PROFILE']
  end

  def setup
    @keytab = Krb5Auth::Krb5::Keytab.new
    @realm  = Krb5Auth::Kadm5::Config.new.realm
    @entry  = nil
    @name   = nil
  end

  test "constructor takes an optional name" do
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/usr/local/var/keytab") }
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/bogus/keytab") }
  end

  test "using an invalid residual type causes an error" do
    omit("Invalid residual type test skipped for now")
    assert_raise(Krb5Auth::Krb5::Keytab::Exception){
      @keytab = Krb5Auth::Krb5::Keytab.new("BOGUS:/bogus/keytab")
    }
  end

  test "keytab name passed to constructor must be a string" do
    assert_raise(TypeError){ Krb5Auth::Krb5::Keytab.new(1) }
  end

  test "name basic functionality" do
    assert_respond_to(@keytab, :name)
    assert_kind_of(String, @keytab.name)
  end

  test "name is set to default name if no argument is passed to constructor" do
    assert_equal(@keytab.name, @keytab.default_name)
  end

  test "name is set to value passed to constructor" do
    temp = "FILE:" + Dir.tmpdir + "/test.keytab"
    @keytab = Krb5Auth::Krb5::Keytab.new(temp)
    assert_equal(@keytab.name, temp)
  end

  test "default_name basic functionality" do
    assert_respond_to(@keytab, :default_name)
    assert_nothing_raised{ @keytab.default_name }
    assert_kind_of(String, @keytab.default_name)
  end

  test "close basic functionality" do
    assert_respond_to(@keytab, :close)
    assert_nothing_raised{ @keytab.close }
    assert_boolean(@keytab.close)
  end

  test "each basic functionality" do
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file) }
    assert_respond_to(@keytab, :each)
    assert_nothing_raised{ @keytab.each{} }
  end

  test "each method yields a keytab entry object" do
    array = []
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file) }
    assert_nothing_raised{ @keytab.each{ |entry| array << entry } }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, array[0])
    assert_true(array.size >= 1)
  end

  test "get_entry basic functionality" do
    assert_respond_to(@keytab, :get_entry)
  end

  test "get_entry returns an entry if found in the keytab" do
    @user = "testuser1@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @entry = @keytab.get_entry(@user) }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, @entry)
  end

  test "get_entry raises an error if no entry is found" do
    @user = "bogus_user@" + @realm
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file) }
    assert_raise(Krb5Auth::Krb5::Exception){ @keytab.get_entry(@user) }
  end

  test "find is an alias for get_entry" do
    assert_respond_to(@keytab, :find)
    assert_alias_method(@keytab, :find, :get_entry)
  end

  test "foreach singleton method basic functionality" do
    assert_respond_to(Krb5Auth::Krb5::Keytab, :foreach)
    assert_nothing_raised{ Krb5Auth::Krb5::Keytab.foreach(@@key_file){} }
  end

  test "foreach singleton method yields keytab entry objects" do
    array = []
    assert_nothing_raised{ Krb5Auth::Krb5::Keytab.foreach(@@key_file){ |entry| array << entry } }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, array[0])
    assert_true(array.size >= 1)
  end

=begin
  # These tests skipped until further notice.

  test "add_entry basic functionality" do
    assert_respond_to(@keytab, :add_entry)
  end

  test "add_entry can add a valid principal" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.add_entry(@user) }
  end

  test "add_entry accepts a vno" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.add_entry(@user, 1) }
  end

  test "add_entry accepts a encoding type" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    enctype = Krb5Auth::Krb5::ENCTYPE_DES_HMAC_SHA1
    assert_nothing_raised{ @keytab.add_entry(@user, 1, enctype) }
  end

  test "add_entry requires at least one argument" do
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(ArgumentError){ @keytab.add_entry }
  end

  test "first argument add_entry must be a string" do
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.add_entry(1) }
  end

  test "second argument to add_entry must be a number" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.add_entry(@user, "test") }
  end

  test "third argument to add_entry must be a number" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.add_entry(@user, 0, "test") }
  end

  test "add_entry accepts a maximum of three arguments" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(ArgumentError){ @keytab.add_entry(@user, 0, 0, 0) }
  end

  test "add_entry does not fail if an bogus user is added" do
    @user = "bogususer@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.add_entry(@user) }
  end

  test "add_entry can be called multiple times" do
    @user = "bogususer@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.add_entry(@user) }
    assert_nothing_raised{ @keytab.add_entry(@user) }
    assert_nothing_raised{ @keytab.add_entry(@user) }
  end

  test "remove_entry basic functionality" do
    assert_respond_to(@keytab, :remove_entry)
  end

  test "remove_entry can add a valid principal" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    @keytab.add_entry(@user)

    assert_nothing_raised{ @keytab.remove_entry(@user) }
  end

  test "remove_entry accepts a vno" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    @keytab.add_entry(@user, 1)
    assert_nothing_raised{ @keytab.remove_entry(@user, 1) }
  end

  test "remove_entry accepts a encoding type" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    enctype = Krb5Auth::Krb5::ENCTYPE_DES_HMAC_SHA1
    @keytab.add_entry(@user, 1, enctype)
    assert_nothing_raised{ @keytab.remove_entry(@user, 1, enctype) }
  end

  test "remove_entry requires at least one argument" do
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(ArgumentError){ @keytab.remove_entry }
  end

  test "first argument remove_entry must be a string" do
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.remove_entry(1) }
  end

  test "second argument to remove_entry must be a number" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.remove_entry(@user, "test") }
  end

  test "third argument to remove_entry must be a number" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(TypeError){ @keytab.remove_entry(@user, 0, "test") }
  end

  test "remove_entry accepts a maximum of three arguments" do
    @user = "testuser2@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_raise(ArgumentError){ @keytab.remove_entry(@user, 0, 0, 0) }
  end

  test "remove_entry does not fail if an bogus user is removed" do
    @user = "bogususer@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.remove_entry(@user) }
  end

  test "remove_entry can be called multiple times" do
    @user = "testuser1@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    @keytab.add_entry(@user)
    assert_nothing_raised{ @keytab.remove_entry(@user) }
    assert_nothing_raised{ @keytab.remove_entry(@user) }
  end

  test "a principal can be added and removed" do
    @user = "testuser1@" + @realm
    @keytab = Krb5Auth::Krb5::Keytab.new(@@key_file)
    assert_nothing_raised{ @keytab.add_entry(@user) }
    assert_nothing_raised{ @keytab.remove_entry(@user) }
  end
=end

  def teardown
    @keytab.close if @keytab
    @keytab = nil
    @entry  = nil
    @realm  = nil
  end

  def self.shutdown
    File.delete(@@key_file) if File.exists?(@@key_file)
    @@key_file = nil
    @@home_dir = nil
  end
end
