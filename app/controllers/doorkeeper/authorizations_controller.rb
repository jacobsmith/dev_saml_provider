module Doorkeeper
  class AuthorizationsController < Doorkeeper::ApplicationController

    def new
      if pre_auth.authorizable?
        puts "PRE_AUTH AUTHORIZABLE"
        if skip_authorization? || matching_token?
          puts "ABOUT TO REDIRECT TO REDIRECT URI"
          auth = authorization.authorize
          redirect_to auth.redirect_uri
        else
          puts "REDNERING NEW"
          render :new
        end
      else
        puts "RENDERING ERROR"
        render :error
      end
    end
    private

    def matching_token?
      true
    end

    def authorization
      OpenStruct.new({
        authorize: OpenStruct.new({
          redirect_uri: params[:redirect_uri] + "?state=#{params[:state]}"
          })
        })
    end

    def pre_auth
      @pre_auth ||= OpenStruct.new(
        {
          authorizable?: true,
          client: OpenStruct.new(name: "I am client, yes")
        }
      )
    end

    def skip_authorization?
      false
    end
  end
end
