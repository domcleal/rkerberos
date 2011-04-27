########################################################################
# test_policy.rb
#
# Tests for the Krb5Auth::Kadm5::Policy class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Kadm5_Policy < Test::Unit::TestCase
  def setup
    @policy = Krb5Auth::Kadm5::Policy.new(:name => 'test', :max_life => 10000)
  end

  test 'policy name basic functionality' do
    assert_respond_to(@policy, :policy)
  end

  test 'policy name alias' do
    assert_respond_to(@policy, :name)
    assert_alias_method(@policy, :name, :policy)
  end

  test 'policy name must be a string' do
    assert_raise(TypeError){ Krb5Auth::Kadm5::Policy.new(:name => 1) }
  end

  test 'policy name must be present' do
    assert_raise(ArgumentError){ Krb5Auth::Kadm5::Policy.new(:max_life => 10000) }
  end

  test 'min_life basic functionality' do
    assert_respond_to(@policy, :min_life)
    assert_nothing_raised{ @policy.min_life }
  end

  test 'min_life must be a number if not nil' do
    assert_raise(TypeError){
      Krb5Auth::Kadm5::Policy.new(:name => 'test', :min_life => 'test')
    }
  end

  test 'max_life basic functionality' do
    assert_respond_to(@policy, :max_life)
    assert_nothing_raised{ @policy.max_life }
  end

  test 'max_life must be a number if not nil' do
    assert_raise(TypeError){
      Krb5Auth::Kadm5::Policy.new(:name => 'test', :max_life => 'test')
    }
  end

  test 'min_length basic functionality' do
    assert_respond_to(@policy, :min_length)
    assert_nothing_raised{ @policy.min_length }
  end

  test 'min_length must be a number if not nil' do
    assert_raise(TypeError){
      Krb5Auth::Kadm5::Policy.new(:name => 'test', :min_length => 'test')
    }
  end

  test 'min_classes basic functionality' do
    assert_respond_to(@policy, :min_classes)
    assert_nothing_raised{ @policy.min_classes }
  end

  test 'min_classes must be a number if not nil' do
    assert_raise(TypeError){
      Krb5Auth::Kadm5::Policy.new(:name => 'test', :min_classes => 'test')
    }
  end

  test 'history_num basic functionality' do
    assert_respond_to(@policy, :history_num)
    assert_nothing_raised{ @policy.history_num }
  end

  test 'history_num must be a number if not nil' do
    assert_raise(TypeError){
      Krb5Auth::Kadm5::Policy.new(:name => 'test', :history_num => 'test')
    }
  end

  test 'instance variables are set as expected from the constructor' do
    @policy = Krb5Auth::Kadm5::Policy.new(
      :name        => 'test',
      :min_life    => 8888,
      :max_life    => 9999,
      :min_length  => 5,
      :min_classes => 2,
      :history_num => 7
    )

    assert_equal('test', @policy.name)
    assert_equal(8888, @policy.min_life)
    assert_equal(9999, @policy.max_life)
    assert_equal(5, @policy.min_length)
    assert_equal(2, @policy.min_classes)
    assert_equal(7, @policy.history_num)
  end

  test 'constructor requires one argument' do
    assert_raise(ArgumentError){ Krb5Auth::Kadm5::Policy.new }
    assert_raise(ArgumentError){ Krb5Auth::Kadm5::Policy.new('foo', 'bar') }
  end

  test 'constructor requires a hash argument' do
    assert_raise(TypeError){ Krb5Auth::Kadm5::Policy.new('test') }
  end

  test 'constructor raises an error if the hash is empty' do
    assert_raise(ArgumentError){ Krb5Auth::Kadm5::Policy.new({}) }
  end

  def teardown
    @policy = nil
  end
end
