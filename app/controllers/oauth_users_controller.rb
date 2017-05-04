class OauthUsersController < ApplicationController
  class User
    def initialize(params)
      params.keys.each do |key|
        define_singleton_method key do
          params[key]
        end
      end
    end

    def name
      'John Smith from OAuth'
    end

    def id
      123
    end

    def email
      "john.smith@example.com"
    end

    def to_json
      {
        "name" => name,
        "id" => id,
        "email" => email
      }
    end
  end

  def me
    render json: User.new(params).to_json
  end
end
