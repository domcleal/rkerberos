#######################################################################
# test_keytab_entry.rb
#
# Test suite for the Krb5Auth::Krb5::KeytabEntry class.
#######################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Krb5_KeytabEntry < Test::Unit::TestCase
  def setup
    @kte = Krb5Auth::Krb5::Keytab::Entry.new
  end

  test "principal getter basic functionality" do
    assert_respond_to(@kte, :principal)
    assert_nothing_raised{ @kte.principal }
  end

  test "principal setter basic functionality" do
    assert_respond_to(@kte, :principal)
    assert_nothing_raised{ @kte.principal = "test" }
    assert_equal("test", @kte.principal)
  end

  test "timestamp getter basic functionality" do
    assert_respond_to(@kte, :timestamp)
    assert_nothing_raised{ @kte.timestamp }
  end

  test "timestamp setter basic functionality" do
    time = Time.now
    assert_respond_to(@kte, :timestamp=)
    assert_nothing_raised{ @kte.timestamp = time }
    assert_equal(time, @kte.timestamp)
  end

  test "vno getter basic functionality" do
    assert_respond_to(@kte, :vno)
    assert_nothing_raised{ @kte.vno }
  end

  test "vno setter basic functionality" do
    time = Time.now
    assert_respond_to(@kte, :vno=)
    assert_nothing_raised{ @kte.vno = time }
    assert_equal(time, @kte.vno)
  end

  test "key getter basic functionality" do
    assert_respond_to(@kte, :vno)
    assert_nothing_raised{ @kte.vno }
  end

  test "key setter basic functionality" do
    assert_respond_to(@kte, :key=)
    assert_nothing_raised{ @kte.key = 23 }
    assert_equal(23, @kte.key)
  end

  def teardown
    @kte = nil
  end
end
