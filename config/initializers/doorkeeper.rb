class User
  def id
    112358
  end

  def name
    "User defined in config init doorkeeper"
  end
end

Doorkeeper.configure do
  resource_owner_authenticator do
    User.new
  end
end

module Doorkeeper
  module AccessGrantMixin
    module ClassMethods
      def find_by(token)
        OpenStruct.new(token: "hello!")
      end
    end
  end

  module AccessTokenMixin
    module ClassMethods
      def find_by(token)
        OpenStruct.new(token: "hello!")
      end
    end
  end


  module OAuth
    module Helpers
      module URIChecker
        def self.valid_for_authorization?(url, client_url)
          true
        end
      end
    end

    class TokenResponse
      def body
        {
          'access_token'  => 'iamthetoken',
          'token_type'    => 'implicit_grant',
          'expires_in'    => 60
        }
      end
    end

    class AuthorizationCodeRequest < BaseRequest
      validate :attributes,   error: :invalid_request
      validate :client,       error: :invalid_client
      validate :grant,        error: :invalid_grant
      validate :redirect_uri, error: :invalid_grant

      attr_accessor :server, :grant, :client, :redirect_uri, :access_token

      def initialize(server, grant, client, parameters = {})
        @server = server
        @client = client
        @grant  = grant
        @redirect_uri = parameters[:redirect_uri]
      end

      private

      def before_successful_response
        puts "before_successful_response"
        grant.transaction do
          grant.lock!
          raise Errors::InvalidGrantReuse if grant.revoked?

          grant.revoke
          find_or_create_access_token(grant.application,
          grant.resource_owner_id,
          grant.scopes,
          server)
        end
      end

      def validate_attributes
        puts "validate_attributes"
        redirect_uri.present?
      end

      def validate_client
        puts "validate_client"
        !!client
      end

      def validate_grant
        puts "validate_grant"
        return true
        return false unless grant && grant.application_id == client.id
        grant.accessible?
      end

      def validate_redirect_uri
        puts "validate_redirect_uri"
        return true
        grant.redirect_uri == redirect_uri
      end
    end

    class Client
      def initialize(application)
        @application = OpenStruct.new({
          id: 123,
          name: "TestApp",
          redirect_url: "IAMAREDIRECTURL",
          scopes: :all
        })
      end

      def self.find(uid, method = nil)
        new(nil)
      end

      def self.authenticate(credentials, method = nil)
        new(nil)
      end
    end
  end
end
