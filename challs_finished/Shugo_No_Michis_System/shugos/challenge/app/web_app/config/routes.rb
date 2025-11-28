Rails.application.routes.draw do
  BASE = ENV.fetch('RAILS_RELATIVE_URL_ROOT', '')

  scope path: BASE do
    resource  :session, only: [:create, :destroy]
    resources :users,   only: [:create]

    resources :tickets do
      member { patch :rebook }
    end

    get  "map",          to: "map#index",   as: :map
    get  "map/tracker",  to: "map#tracker", as: :map_tracker

    namespace :admin do
      root 'dashboard#index'
      resources :users,  only: [:index, :update]
      resources :tickets, only: [:index, :show, :update]
      get 'parser',          to: 'parser#index'
      get 'parser/tickets',  to: 'parser#tickets'
    end

    root 'home#index'
  end
end
