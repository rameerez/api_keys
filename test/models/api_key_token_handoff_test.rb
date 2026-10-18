# frozen_string_literal: true

require "test_helper"

module ApiKeys
  # The durable half of the one-time token handoff (0.6.0): the atomic claim
  # of `token_shown_at` and the predicates around it.
  class ApiKeyTokenHandoffTest < ApiKeys::Test
    def setup
      super
      @user = User.create!(name: "Handoff Owner")
      @key = @user.create_api_key!(name: "Handoff")
    end

    test "a new key has not been shown" do
      assert ApiKey.token_shown_at_column?
      assert_nil @key.token_shown_at
      refute @key.token_shown?
      assert ApiKey.token_handoff_claimable?(@key.id)
    end

    test "exactly one claim succeeds, and it stamps the key" do
      freeze_time do
        assert ApiKey.claim_token_handoff!(@key.id)
        assert_equal Time.current.to_i, @key.reload.token_shown_at.to_i
      end

      refute ApiKey.claim_token_handoff!(@key.id), "a second claim changes no row"
      refute ApiKey.claim_token_handoff!(@key.id.to_s), "nor does the same ID as a string"
      refute ApiKey.token_handoff_claimable?(@key.id)
      assert @key.reload.token_shown?
    end

    test "a claim touches only its own key" do
      other = @user.create_api_key!(name: "Other")

      assert ApiKey.claim_token_handoff!(@key.id)

      refute other.reload.token_shown?
      assert ApiKey.claim_token_handoff!(other.id)
    end

    test "claims for a missing, nil, or nonsense ID fail closed" do
      missing_id = @key.id + 1_000

      refute ApiKey.claim_token_handoff!(missing_id)
      refute ApiKey.claim_token_handoff!(nil)
      refute ApiKey.claim_token_handoff!("not-an-id")
      refute ApiKey.token_handoff_claimable?(missing_id)
      refute ApiKey.token_handoff_claimable?(nil)
      refute @key.reload.token_shown?, "none of them stamped an existing key"
    end

    test "ordinary saves can neither set nor clear token_shown_at" do
      ApiKey.claim_token_handoff!(@key.id)
      shown_at = @key.reload.token_shown_at

      [nil, 1.day.ago].each do |value|
        begin
          @key.update(token_shown_at: value)
        rescue ActiveRecord::ActiveRecordError
          nil # raise_on_assign_to_attr_readonly refuses the assignment outright
        end
        assert_equal shown_at.to_i, @key.reload.token_shown_at.to_i
      end
    end

    test "without the column everything answers as before 0.6.0" do
      TokenShownAtSchema.without_column do
        refute ApiKey.token_shown_at_column?
        key = ApiKey.find(@key.id)
        assert_nil key.token_shown_at
        refute key.token_shown?
        assert_nil ApiKey.claim_token_handoff!(key.id), "nothing can be recorded durably"
        assert_nil ApiKey.token_handoff_claimable?(key.id)
      end
    end

    test "the claim raises on database errors so the caller can withhold the token" do
      ApiKey.stubs(:where).raises(ActiveRecord::StatementInvalid, "database unavailable")

      assert_raises(ActiveRecord::StatementInvalid) { ApiKey.claim_token_handoff!(@key.id) }
    end
  end
end
