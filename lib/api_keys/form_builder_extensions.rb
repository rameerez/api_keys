# frozen_string_literal: true

module ApiKeys
  # Opt-in form builder extensions for API key forms.
  #
  # These helpers reduce boilerplate while letting you control the styling.
  # Include them in your form builder to use:
  #
  #   # In config/initializers/api_keys.rb:
  #   Rails.application.config.to_prepare do
  #     ActionView::Helpers::FormBuilder.include(ApiKeys::FormBuilderExtensions)
  #   end
  #
  # @example Expiration select
  #   <%= form.api_key_expiration_select(class: "my-select-class") %>
  #
  # @example Scopes checkboxes with block for custom rendering
  #   <%= form.api_key_scopes_checkboxes(@scopes) do |scope, checked| %>
  #     <label>
  #       <%= check_box_tag "api_key[scopes][]", scope, checked, class: "my-checkbox" %>
  #       <%= scope %>
  #     </label>
  #   <% end %>
  #   (The helper prepends an empty `api_key[scopes][]` sentinel so that
  #   clearing every box submits "no scopes" instead of nothing.)
  #
  module FormBuilderExtensions
    # Renders a select field for API key expiration presets.
    #
    # @param options [Hash] Options passed to the select helper
    # @param html_options [Hash] HTML attributes for the select element
    # @return [String] HTML select element
    #
    # @example Basic usage
    #   <%= form.api_key_expiration_select %>
    #
    # @example With Tailwind classes
    #   <%= form.api_key_expiration_select(class: "w-full px-4 py-3 border rounded-lg") %>
    #
    # @example With custom default
    #   <%= form.api_key_expiration_select(selected: "30_days") %>
    #
    def api_key_expiration_select(options = {}, html_options = {})
      # expires_at_preset is a form-only param, not a model attribute
      # So we only use the provided :selected option or default
      selected = options.delete(:selected) || ApiKeys::ExpirationOptions.default_value

      select(
        :expires_at_preset,
        @template.options_for_select(ApiKeys::ExpirationOptions.for_select, selected),
        options,
        html_options
      )
    end

    # Renders checkboxes for API key scopes.
    #
    # If a block is given, yields each scope and its checked state for custom rendering.
    # If no block is given, returns an array of checkbox data for manual iteration.
    #
    # @param scopes [Array<String>] Available scopes to render
    # @param checked [Symbol, Array] Which scopes should be checked:
    #   - :all (default for new records) - all scopes checked
    #   - :none - no scopes checked
    #   - Array - specific scopes to check
    #   - nil - uses the object's current scopes
    # @param include_hidden [Boolean, nil] With a block, whether to render an
    #   empty `name="api_key[scopes][]" value=""` sentinel before the boxes.
    #   Browsers omit unchecked boxes, so without it clearing every box submits
    #   no scopes parameter at all, and a create would silently get the default
    #   scopes while an update would keep the old ones. With the sentinel the
    #   server receives `[""]`, which `ApiKey#scopes=` and `create_api_key!`
    #   read as "no scopes". The submitted list replaces the key's scopes, so
    #   render a box for every scope the key may hold.
    #   - nil (default): render it when there is at least one box and the
    #     form's key enforces its scopes (`ApiKey#scopes_enforced?`). Elsewhere
    #     an empty list would mean "unrestricted" and clearing the boxes would
    #     widen the key. Per-owner default scopes are read through the key's
    #     `owner`, so build the form's key from its owner
    #     (`owner.api_keys.build`): a form with no object, or on a bare
    #     `ApiKey.new`, cannot see them and renders no sentinel.
    #   - true: render it whenever there is at least one box, without asking
    #     the key. Use it on those ownerless forms when an empty list grants
    #     nothing in your app.
    #   - false: never render it.
    # @return [String, Array] HTML if block given, otherwise array of scope data
    #
    # @example With block (recommended for custom styling)
    #   <%= form.api_key_scopes_checkboxes(@scopes) do |scope, checked| %>
    #     <label class="flex items-center gap-2">
    #       <%= check_box_tag "api_key[scopes][]", scope, checked, class: "rounded" %>
    #       <code><%= scope %></code>
    #     </label>
    #   <% end %>
    #
    # @example Simple rendering without block (render the sentinel yourself)
    #   <%= hidden_field_tag "api_key[scopes][]", "", id: nil %>
    #   <% form.api_key_scopes_checkboxes(@scopes).each do |scope_data| %>
    #     <%= check_box_tag "api_key[scopes][]", scope_data[:value], scope_data[:checked] %>
    #     <%= scope_data[:value] %>
    #   <% end %>
    #
    def api_key_scopes_checkboxes(scopes, checked: nil, include_hidden: nil, &block)
      # Determine which scopes should be checked
      checked_scopes = resolve_checked_scopes(scopes, checked)
      field_name = "#{object_name}[scopes][]"

      scope_data = scopes.map do |scope|
        {
          value: scope,
          checked: checked_scopes.include?(scope),
          field_name: field_name
        }
      end

      if block_given?
        # Yield each scope for custom rendering
        safe_buffer = ActiveSupport::SafeBuffer.new
        safe_buffer << @template.hidden_field_tag(field_name, "", id: nil) if render_scope_sentinel?(scopes, include_hidden)
        scope_data.each do |data|
          safe_buffer << @template.capture { yield(data[:value], data[:checked]) }
        end
        safe_buffer
      else
        # Return raw data for manual iteration
        scope_data
      end
    end

    # Returns structured data for building a token display UI.
    # Useful when you need to build a custom token display with copy functionality.
    #
    # @return [Hash] Token display data with keys:
    #   - :masked [String] The masked token (e.g., "sk_live_••••abc")
    #   - :full [String, nil] The full token (only for viewable public keys)
    #   - :viewable [Boolean] Whether the full token can be displayed
    #   - :type [Symbol, String, nil] A known built-in type is a Symbol; custom
    #     untrusted values remain Strings so they are never interned as Symbols.
    #   - :environment [String, nil] The environment (e.g., "live", "test")
    #
    # @example
    #   <% data = form.api_key_token_data %>
    #   <code><%= data[:masked] %></code>
    #   <% if data[:viewable] %>
    #     <button data-token="<%= data[:full] %>">Copy</button>
    #   <% end %>
    #
    def api_key_token_data
      return {} unless object.respond_to?(:masked_token)

      {
        masked: object.masked_token,
        full: object.viewable_token,
        viewable: object.respond_to?(:public_key_type?) && object.public_key_type?,
        type: safe_key_type(object.key_type),
        environment: object.environment
      }
    end

    private

    # The sentinel is only safe where an empty list grants nothing. With no
    # boxes there is nothing to clear, so it is never rendered then. By
    # default it also needs a key that enforces its scopes; where the key does
    # not, an empty list would mean "unrestricted", so the parameter is left
    # out and the key keeps the scopes it has. `include_hidden: true` skips
    # that question for forms whose key cannot answer it.
    def render_scope_sentinel?(scopes, include_hidden)
      return false if include_hidden == false || scopes.empty?
      return true if include_hidden == true

      object.respond_to?(:scopes_enforced?) && object.scopes_enforced?
    end

    def safe_key_type(value)
      case value.to_s
      when "publishable" then :publishable
      when "secret" then :secret
      when "" then nil
      else value.to_s
      end
    end

    def resolve_checked_scopes(scopes, checked)
      case checked
      when :all
        scopes.map(&:to_s)
      when :none
        []
      when Array
        checked.map(&:to_s)
      when nil
        # For new records, default to all checked
        # For existing records, use the object's scopes
        if object&.persisted?
          (object.scopes || []).map(&:to_s)
        else
          scopes.map(&:to_s)
        end
      else
        scopes.map(&:to_s)
      end
    end
  end
end
