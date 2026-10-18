# frozen_string_literal: true

require "test_helper"
require "action_view"
require "nokogiri"
require "rack"

module ApiKeys
  class FormBuilderExtensionsTest < ApiKeys::Test
    FakeObject = Struct.new(:persisted?, :scopes, :key_type, :environment, keyword_init: true) do
      def masked_token = "pk_test_••••abcd"
      def viewable_token = "pk_test_full"
      def public_key_type? = true
    end

    class FakeTemplate
      def options_for_select(options, selected)
        { options: options, selected: selected }
      end

      def capture
        yield
      end
    end

    class FakeBuilder
      include ApiKeys::FormBuilderExtensions

      attr_reader :object, :object_name, :template

      def initialize(object: nil)
        @object = object
        @object_name = "api_key"
        @template = FakeTemplate.new
      end

      def select(*arguments)
        arguments
      end
    end

    test "expiration select honors a selected preset and preserves options" do
      builder = FakeBuilder.new

      arguments = builder.api_key_expiration_select({ selected: "30_days", include_blank: true }, class: "expiry")

      assert_equal :expires_at_preset, arguments[0]
      assert_equal "30_days", arguments[1][:selected]
      assert_equal({ include_blank: true }, arguments[2])
      assert_equal({ class: "expiry" }, arguments[3])
      assert_equal ApiKeys::ExpirationOptions.default_value,
                   builder.api_key_expiration_select[1][:selected]
    end

    test "scope data supports every checked policy" do
      new_builder = FakeBuilder.new(object: FakeObject.new(persisted?: false, scopes: ["read"]))
      persisted_builder = FakeBuilder.new(object: FakeObject.new(persisted?: true, scopes: ["write"]))
      scopes = %w[read write]

      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes, checked: :all).pluck(:checked)
      assert_equal [false, false], new_builder.api_key_scopes_checkboxes(scopes, checked: :none).pluck(:checked)
      assert_equal [false, true], new_builder.api_key_scopes_checkboxes(scopes, checked: [:write]).pluck(:checked)
      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes).pluck(:checked)
      assert_equal [false, true], persisted_builder.api_key_scopes_checkboxes(scopes).pluck(:checked)
      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes, checked: Object.new).pluck(:checked)
      assert_equal "api_key[scopes][]", new_builder.api_key_scopes_checkboxes(scopes).first[:field_name]
    end

    test "scope rendering captures each custom row into a safe buffer" do
      builder = FakeBuilder.new

      html = builder.api_key_scopes_checkboxes(%w[read write], checked: [:read], include_hidden: false) do |scope, checked|
        ERB::Util.html_escape("<#{scope}:#{checked}>")
      end

      assert_instance_of ActiveSupport::SafeBuffer, html
      assert_equal "&lt;read:true&gt;&lt;write:false&gt;", html
    end

    # 0.5.1: the host-facing checkbox group has the same problem the dashboard
    # had. With every box cleared the browser sends nothing, so a create got
    # the default scopes and an update kept the old ones.
    test "a fully cleared host scope group submits none, which creates and updates keys with no scopes" do
      user = User.create!(name: "Host Form Owner")
      configure_owner_scopes(%w[read write])

      new_form = render_scope_group(%w[read write], object: user.api_keys.build, checked: :none)
      created = user.create_api_key!(name: "Host Created", scopes: host_params(new_form)["scopes"])
      assert_equal [], created.scopes, "a cleared group must not create a key with the default scopes"
      refute created.allows_scope?("read")

      existing = user.create_api_key!(name: "Host Existing", scopes: %w[read])
      edit_form = render_scope_group(%w[read write], object: existing, checked: :none)
      assert existing.update(host_params(edit_form))
      assert_equal [], existing.reload.scopes, "a cleared group must not keep the old scopes"
      refute existing.allows_scope?("read")
    end

    test "the host scope group still submits the boxes that are checked" do
      user = User.create!(name: "Host Form Owner")
      configure_owner_scopes(%w[read write])

      html = render_scope_group(%w[read write], object: user.api_keys.build, checked: [:write])

      assert_equal ["", "write"], submitted_scopes(html)
      assert_equal 1, Nokogiri::HTML(html).css('input[type="hidden"][name="api_key[scopes][]"][value=""]').size
    end

    # Where scopes are not enforced (no key types, no default_scopes), an empty
    # list means "unrestricted". Clearing the boxes there must keep the old
    # list rather than widen the key.
    test "the host scope group never submits an empty list where it would mean unrestricted" do
      user = User.create!(name: "Unscoped Host Owner")
      key = user.create_api_key!(name: "Reader", scopes: %w[read])
      refute key.scopes_enforced?, "precondition: this app configures no scopes"
      refute key.allows_scope?("write"), "precondition: the stored list restricts the key"

      html = render_scope_group(%w[read write], object: key, checked: :none)

      assert_nil submitted_scopes(html)
      assert key.update(host_params(html))
      assert_equal %w[read], key.reload.scopes
      refute key.allows_scope?("write")
    end

    test "the host scope group renders no sentinel without any boxes" do
      user = User.create!(name: "Host Form Owner")
      configure_owner_scopes(%w[read])

      assert_nil submitted_scopes(render_scope_group([], object: user.api_keys.build))
      assert_nil submitted_scopes(render_scope_group([], object: user.api_keys.build, include_hidden: true))
      assert_nil submitted_scopes(render_scope_group(%w[read], object: Object.new, checked: :none))
    end

    # Per-owner default scopes are read through the key's owner. A form built
    # with `scope:` and no object, or on a bare ApiKey.new, cannot see them,
    # so by default it renders no sentinel and a fully cleared group still
    # creates a key with the defaults. `include_hidden: true` forces it.
    test "an ownerless form needs include_hidden: true for a cleared group to mean none" do
      user = User.create!(name: "Host Form Owner")
      configure_owner_scopes(%w[read write])
      refute ApiKeys::ApiKey.new.scopes_enforced?, "precondition: a bare key cannot see per-owner defaults"

      { "no object (form_with scope:)" => nil, "a bare ApiKey.new" => ApiKeys::ApiKey.new }.each do |shape, object|
        default_form = render_scope_group(%w[read write], object: object, checked: :none)
        assert_nil submitted_scopes(default_form), "#{shape}: no sentinel by default"
        defaulted = user.create_api_key!(name: "Defaulted", scopes: host_params(default_form)["scopes"])
        assert_equal %w[read write], defaulted.scopes, "#{shape}: the documented default-path limitation"

        forced_form = render_scope_group(%w[read write], object: object, checked: :none, include_hidden: true)
        assert_equal [""], submitted_scopes(forced_form), "#{shape}: include_hidden: true forces the sentinel"
        cleared = user.create_api_key!(name: "Cleared", scopes: host_params(forced_form)["scopes"])
        assert_equal [], cleared.scopes, "#{shape}: a forced sentinel makes the cleared group mean none"
      end
    end

    test "include_hidden: true also forces the sentinel where scopes are not enforced" do
      user = User.create!(name: "Unscoped Host Owner")
      key = user.create_api_key!(name: "Reader", scopes: %w[read])
      refute key.scopes_enforced?

      assert_equal [""], submitted_scopes(render_scope_group(%w[read write], object: key, checked: :none,
                                                                             include_hidden: true))
    end

    test "the host scope group sentinel can be turned off" do
      user = User.create!(name: "Host Form Owner")
      configure_owner_scopes(%w[read write])

      html = render_scope_group(%w[read write], object: user.api_keys.build, checked: :none, include_hidden: false)

      assert_nil submitted_scopes(html)
    end

    test "token data is empty for unrelated objects and safe for every key type" do
      assert_empty FakeBuilder.new(object: Object.new).api_key_token_data

      {
        "publishable" => :publishable,
        "secret" => :secret,
        "" => nil,
        "custom-client" => "custom-client"
      }.each do |raw_type, expected_type|
        object = FakeObject.new(persisted?: true, scopes: [], key_type: raw_type, environment: "test")
        data = FakeBuilder.new(object: object).api_key_token_data

        expected_type.nil? ? assert_nil(data[:type]) : assert_equal(expected_type, data[:type])
        assert_equal "pk_test_full", data[:full]
        assert data[:viewable]
      end
    end

    private

    def configure_owner_scopes(scopes)
      settings = User.api_keys_settings.merge(default_scopes: scopes.map(&:freeze).freeze).freeze
      User.stubs(:api_keys_settings).returns(settings)
    end

    # Renders the group with a real Action View form builder, as a host form would.
    def render_scope_group(scopes, object:, **options)
      view = ActionView::Base.empty
      builder = ActionView::Helpers::FormBuilder.new(:api_key, object, view, {})
      builder.extend(ApiKeys::FormBuilderExtensions)
      builder.api_key_scopes_checkboxes(scopes, **options) do |scope, checked|
        view.check_box_tag("api_key[scopes][]", scope, checked, id: "scope_#{scope}")
      end
    end

    # What a browser submits for the group, parsed the way Rack parses it.
    def submitted_scopes(html)
      pairs = Nokogiri::HTML(html).css("input").filter_map do |input|
        next if input["type"] == "checkbox" && !input.has_attribute?("checked")

        [input["name"], input["value"]]
      end
      Rack::Utils.parse_nested_query(URI.encode_www_form(pairs)).dig("api_key", "scopes")
    end

    # What `params.require(:api_key).permit(:name, scopes: [])` hands a host
    # controller: `scopes` is present only if the browser sent it.
    def host_params(html)
      submitted = submitted_scopes(html)
      params = { "name" => "Host Key" }
      params["scopes"] = submitted unless submitted.nil?
      params
    end
  end
end
