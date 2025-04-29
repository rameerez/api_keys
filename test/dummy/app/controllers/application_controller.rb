class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  # allow_browser versions: :modern

  helper_method :current_user

  # Provides the currently authenticated user for the demo application.
  # Creates a unique test user associated with the session. If the session ID
  # is unavailable, it generates a persistent random identifier stored in the session.
  #
  # @return [User] The found or created user for the current session.
  def current_user
    @current_user ||= begin
      # Ensure a consistent identifier for the demo user throughout their interaction.
      # Prefer an existing identifier stored specifically for this purpose.
      session_identifier = session[:demo_user_identifier]

      if session_identifier.blank?
        # If no identifier is stored yet, try using the session ID.
        # If the session ID is also unavailable, generate a new secure random identifier.
        session_identifier = session&.id || SecureRandom.hex(16)
        # Store the determined identifier in the session for subsequent requests.
        session[:demo_user_identifier] = session_identifier
      end

      # Find or create a user based on the unique session identifier.
      User.find_or_create_by!(email: "demo-#{session_identifier}@example.com")
    end
  end

  # Resets the demo state by deleting the current user and associated data.
  # Clears the session identifier to ensure a fresh start on the next request.
  def reset_demo!
    if user_to_reset = current_user # Use local variable for clarity and efficiency
      # Destroy the user. Associated records (ApiKeys::ApiKey) should be configured with
      # `dependent: :destroy` or similar in the User model for cascading deletion.
      user_to_reset.destroy

      # Clear the memoized current_user instance variable.
      @current_user = nil
      # Remove the specific identifier from the session to force regeneration on next visit.
      session.delete(:demo_user_identifier)
    end

    # Redirect to the application's root path after resetting the demo.
    redirect_to root_path, notice: "The demo has been successfully reset."
  end
end
