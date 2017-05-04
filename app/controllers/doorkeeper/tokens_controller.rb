module Doorkeeper
  class TokensController < Doorkeeper::ApplicationMetalController
    def create
      puts "ABOUT TO CREATE TOKEN"
      response = authorize_response

      puts "RESPONSE HAS BEEN AUTHORIZED"

      headers.merge! response.headers

      puts "headers have been merged"

      self.response_body = response.body.to_json

      puts "response body has been updated"
      self.status        = response.status

      puts "status has been set"

      self.status
    rescue Errors::DoorkeeperError => e
      puts "OH SHIT, DOORKEEPER ERROR!\n#{e}"
      handle_token_exception e
    end

    private

    def token
      puts "CALLING TOKEN!"
      @token ||= AccessToken.by_token(request.POST['token']) ||
      AccessToken.by_refresh_token(request.POST['token'])
    end

    def strategy
      @strategy ||= server.token_request params[:grant_type]
      puts "STRATEGY:\n" + @strategy.inspect
      @strategy
    end

    def authorize_response
      @authorize_response ||= strategy.authorize
    end
  end
end
