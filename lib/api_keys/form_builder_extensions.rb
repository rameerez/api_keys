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
    # @example Simple rendering without block
    #   <% form.api_key_scopes_checkboxes(@scopes).each do |scope_data| %>
    #     <%= check_box_tag "api_key[scopes][]", scope_data[:value], scope_data[:checked] %>
    #     <%= scope_data[:value] %>
    #   <% end %>
    #
    def api_key_scopes_checkboxes(scopes, checked: nil, &block)
      # Determine which scopes should be checked
      checked_scopes = resolve_checked_scopes(scopes, checked)

      scope_data = scopes.map do |scope|
        {
          value: scope,
          checked: checked_scopes.include?(scope),
          field_name: "#{object_name}[scopes][]"
        }
      end

      if block_given?
        # Yield each scope for custom rendering
        safe_buffer = ActiveSupport::SafeBuffer.new
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
    #   - :type [Symbol] The key type (:publishable, :secret, or nil)
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
        type: object.key_type&.to_sym,
        environment: object.environment
      }
    end

    private

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
