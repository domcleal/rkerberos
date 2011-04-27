#######################################################################
# test_credentials_cache.rb
#
# Tests for the Krb5Auth::Krb5::Credentials class.
#######################################################################
require 'rubygems'
gem 'test-unit'

require 'etc'
require 'test/unit'
require 'krb5_auth'
require 'open3'
require 'tmpdir'

class TC_Krb5_Credentials_Cache < Test::Unit::TestCase
  def setup
    @login  = Etc.getlogin
    @princ  = @login + '@' + Krb5Auth::Krb5.new.default_realm
    @cfile  = File.join(Dir.tmpdir, 'krb5cc_' + Etc.getpwnam(@login).uid.to_s)
    @ccache = nil
  end

  # Helper method that uses the command line utility for external verification
  def cache_found
    found = true

    Open3.popen3('klist') do |stdin, stdout, stderr|
      found = false unless stderr.gets.nil?
    end

    found
  end

  # Constructor

  test "calling constructor with no arguments is legal" do
    assert_nothing_raised{ @ccache = Krb5Auth::Krb5::CredentialsCache.new }
  end

  test "calling constructor with no arguments does not create a cache" do
    assert_nothing_raised{ @ccache = Krb5Auth::Krb5::CredentialsCache.new }
    assert_false(File.exists?(@cfile))
    assert_false(cache_found)
  end

  test "calling constructor with a principal argument creates a credentials cache" do
    assert_nothing_raised{ @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ) }
    assert_true(File.exists?(@cfile))
    assert_true(cache_found)
  end

  test "calling constructor with an explicit cache name works as expected" do
    assert_nothing_raised{ @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ, @cfile) }
    assert_nothing_raised{ @ccache = Krb5Auth::Krb5::CredentialsCache.new(nil, @cfile) }
  end

  test "calling constructor with a non string argument raises an error" do
    assert_raise(TypeError){ Krb5Auth::Krb5::CredentialsCache.new(true) }
  end

  test "constructor only accepts up to two arguments" do
    assert_raise(ArgumentError){ Krb5Auth::Krb5::CredentialsCache.new(@princ, @cfile, @cfile) }
  end

  test "close method basic functionality" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_respond_to(@ccache, :close)
  end

  test "close method does not delete credentials cache" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_nothing_raised{ @ccache.close }
    assert_true(cache_found)
  end

  test "calling close multiple times on the same object does not raise an error" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
  end

  test "calling a method on a closed object raises an error" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    @ccache.close
    assert_raise(Krb5Auth::Krb5::Exception){ @ccache.default_name }
  end

  test "default_name basic functionality" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_respond_to(@ccache, :default_name)
    assert_nothing_raised{ @ccache.default_name }
  end

  test "default_name returns a string" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_kind_of(String, @ccache.default_name)
  end

  test "primary_principal basic functionality" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_respond_to(@ccache, :primary_principal)
    assert_nothing_raised{ @ccache.primary_principal }
  end

  test "primary_principal returns expected results" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_kind_of(String, @ccache.primary_principal)
    assert_true(@ccache.primary_principal.size > 0)
    assert_true(@ccache.primary_principal.include?("@"))
  end

  test "destroy method basic functionality" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_respond_to(@ccache, :destroy)
  end

  test "destroy method deletes credentials cache" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_nothing_raised{ @ccache.destroy }
    assert_false(cache_found)
  end

  test "delete is an alias for destroy" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_respond_to(@ccache, :delete)
    assert_alias_method(@ccache, :destroy, :delete)
  end

  test "calling destroy when there is no credentials cache returns false" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new
    assert_false(@ccache.destroy)
  end

  test "calling a method on a destroyed object raises an error" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    @ccache.destroy
    assert_raise(Krb5Auth::Krb5::Exception){ @ccache.default_name }
  end

  test "destroy method does not accept any arguments" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_raise(ArgumentError){ @ccache.destroy(true) }
  end

  def teardown
    @login  = nil
    @princ  = nil
    @ccache = nil
    @cname  = nil
    Open3.popen3('kdestroy'){ sleep 0.1 } # Ignore errors and wait a tiny bit
  end
end
