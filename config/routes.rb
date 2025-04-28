# frozen_string_literal: true

ApiKeys::Engine.routes.draw do
  # User-facing API Key management
  resources :keys, only: [:index, :new, :create, :show, :edit, :update] do
    member do
      post :revoke # Using POST for actions that change state
    end
  end

  # Static pages
  namespace :security do
    get :best_practices
  end

  # Root of the engine could point to the keys index
  root to: "keys#index"
end
