class User
  attr_reader :email, :password, :params
  def initialize(email:, password:, params:)
    @email = email
    @password = password
    @params = params
  end

  # I think this is akin to an "id"
  def persistent
    123
  end

  def valid_password?
    password == "password"
  end

  def name
    email.split("@").first.gsub(/(\+|_|\.)/, " ")
  end

  def id
    params[:user_id].presence || Digest::MD5.hexdigest(email)
  end

  def asserted_attributes
    {
      email: {
        name: "urn:oid:0.9.2342.19200300.100.1.3",
      },
      nickname: {
        getter: :name,
        name: "urn:oid:2.5.4.3"
      },
      user_id_attribute: {
        getter: :id,
        name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
      }
    }
  end
end


## Parent class!
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable unless Rails::VERSION::MAJOR >= 4
    protect_from_forgery
    before_filter :validate_saml_request, only: [:new, :create]

    def new
      render template: "saml_idp/idp/new"
    end

    def show
      render xml: SamlIdp.metadata.signed
    end

    def create
      unless params[:email].blank? && params[:password].blank?
        person = idp_authenticate(params[:email], params[:password], params)
        if person.nil?
          @saml_idp_fail_msg = "Incorrect email or password."
        else
          @saml_response = idp_make_saml_response(person)
          render :template => "saml_idp/idp/saml_post", :layout => false
          return
        end
      end
      render :template => "saml_idp/idp/new"
    end

    def logout
      idp_logout
      @saml_response = idp_make_saml_response(nil)
      render :template => "saml_idp/idp/saml_post", :layout => false
    end

    def idp_logout
      raise NotImplementedError
    end
    private :idp_logout

    def idp_authenticate(email, password)
      raise NotImplementedError
    end
    protected :idp_authenticate

    def idp_make_saml_response(person)
      raise NotImplementedError
    end
    protected :idp_make_saml_response
  end
end



class SamlIdpController < SamlIdp::IdpController
  def new
    render "new"
  end

  def idp_authenticate(email, password, params) # not using params intentionally
    user = User.new(email: email, password: password, params: params)
    user && user.valid_password? ? user : nil
  end
  private :idp_authenticate

  def idp_make_saml_response(found_user) # not using params intentionally
    encode_response(found_user)
  end
  private :idp_make_saml_response

  def idp_logout
    true # mimic logout
  end
  private :idp_logout

  def encode_authn_response_show
    # render idp-initiated view
  end

  def encode_authn_response
    principal = User.new(email: params[:email], password: params[:password], params: params)

    opts = {} # defaults to '{}' in super

    response_id = get_saml_response_id
    reference_id = opts[:reference_id] || get_saml_reference_id
    saml_acs_url = params[:saml_acs_url]
    audience_uri = params[:audience_uri] || opts[:audience_uri] || saml_request.issuer || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
    opt_issuer_uri = opts[:issuer_uri] || issuer_uri
    my_authn_context_classref = authn_context_classref
    expiry = opts[:expiry] || 60*60
    encryption_opts = opts[:encryption] || nil
    saml_request_id = nil # no request id, it's idP

    response = SamlIdp::SamlResponse.new(
      reference_id,
      response_id,
      opt_issuer_uri,
      principal,
      audience_uri,
      saml_request_id,
      saml_acs_url,
      (opts[:algorithm] || algorithm || default_algorithm),
      my_authn_context_classref,
      expiry,
      encryption_opts
    ).build

    # This is the world's crappiest way to make sure that the "InResponseTo" parameter is not included.
    # Crappy, but it works. =P
    response = Base64.decode64(response)
    response.gsub!("InResponseTo=\"\"", "")
    response = Base64.encode64(response)

    render "idp-initiated-response", locals: { saml_acs_url: saml_acs_url, responseParams: { SAMLResponse: response } }
  end
end
