Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  # root "posts#index"

  # Mount the ApiKeys engine for a hosted portal for managing keys
  mount ApiKeys::Engine => '/settings/api-keys'

  # Define routes for the demo controller
  root "api_keys#index"

  get "/api_keys" => "api_keys#index"

  # Demo API endpoints to test authentication and scopes
  scope "/demo_api", controller: :api_keys do
    get "/public", to: "api_keys#public_action"
    get "/authenticated", to: "api_keys#authenticated_action"
    get "/scoped/read", to: "api_keys#read_action"
    # Add a POST endpoint for write/admin to show method handling
    post "/scoped/write", to: "api_keys#write_action"
    get "/scoped/admin", to: "api_keys#admin_action"

    # New route for rate limiting demo
    get "/rate_limited", to: "api_keys#rate_limited_action"

    # Potentially add routes for testing tenant resolution later
    # get "/tenant_info", to: "api_keys#tenant_action"
  end

  # Allow visitors to reset their demo state
  get "/reset_demo", to: "application#reset_demo!", as: :reset_demo_path
end
