# frozen_string_literal: true

require "test_helper"

module ApiKeys
  # Engine views must use their own (engine-relative) route helpers, never
  # the host-side routes proxy. `api_keys.keys_path` works only when the
  # host mounts the engine under its default name — a custom mount
  # (`mount ApiKeys::Engine => "...", as: :settings_api_keys`) renames the
  # proxy and every hardcoded call explodes with
  # `undefined local variable 'api_keys'`. Inside engine views the bare
  # helpers (`keys_path`) resolve against the engine's OWN routes under any
  # mount name, so the proxy is never needed there.
  #
  # This is a source lint rather than a rendered test because the suite
  # deliberately runs without booting the dummy app; the dummy's second
  # mount (`/renamed-keys`, custom `as:`) covers manual verification.
  class ViewsRouteHelpersTest < ApiKeys::Test
    VIEWS_GLOB = File.expand_path("../app/views/api_keys/**/*.erb", __dir__)
    PROXY_CALL = /\bapi_keys\.\w+_(?:path|url)\b/

    test "no engine view calls the host-side api_keys routes proxy" do
      offenders = Dir.glob(VIEWS_GLOB).filter_map do |file|
        matches = File.read(file).scan(PROXY_CALL)
        [ file, matches ] if matches.any?
      end

      assert_empty offenders,
        "Engine views must use engine-relative helpers (keys_path, not api_keys.keys_path); " \
        "offenders: #{offenders.map(&:first).join(", ")}"
    end
  end
end
