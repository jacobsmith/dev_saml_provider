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

  module ::SamlIdp
    class ResponseBuilder
      def build
        builder = Builder::XmlMarkup.new
        builder.tag! "samlp:Response",
        ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: saml_acs_url,
        Consent: Saml::XML::Namespaces::Consents::UNSPECIFIED,
        "xmlns:samlp" => Saml::XML::Namespaces::PROTOCOL do |response|
          response.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          response.tag! "samlp:Status" do |status|
            status.tag! "samlp:StatusCode", Value: Saml::XML::Namespaces::Statuses::SUCCESS
          end
          response << assertion_and_signature
        end
      end
    end

    class AssertionBuilder
      # This redefines #raw to be exactly the same as usual, but without a "InResponseTo" parameter
      def raw
        builder = Builder::XmlMarkup.new
        builder.Assertion xmlns: Saml::XML::Namespaces::ASSERTION,
        ID: reference_string,
        IssueInstant: now_iso,
        Version: "2.0" do |assertion|
          assertion.Issuer issuer_uri
          sign assertion
          assertion.Subject do |subject|
            subject.NameID name_id, Format: name_id_format[:name]
            subject.SubjectConfirmation Method: Saml::XML::Namespaces::Methods::BEARER do |confirmation|
              confirmation.SubjectConfirmationData "",
              NotOnOrAfter: not_on_or_after_subject,
              Recipient: saml_acs_url
            end
          end
          assertion.Conditions NotBefore: not_before, NotOnOrAfter: not_on_or_after_condition do |conditions|
            conditions.AudienceRestriction do |restriction|
              restriction.Audience audience_uri
            end
          end
          if asserted_attributes
            assertion.AttributeStatement do |attr_statement|
              asserted_attributes.each do |friendly_name, attrs|
                attrs = (attrs || {}).with_indifferent_access
                attr_statement.Attribute Name: attrs[:name] || friendly_name,
                NameFormat: attrs[:name_format] || Saml::XML::Namespaces::Formats::Attr::URI,
                FriendlyName: friendly_name.to_s do |attr|
                  values = get_values_for friendly_name, attrs[:getter]
                  values.each do |val|
                    attr.AttributeValue val.to_s
                  end
                end
              end
            end
          end
          assertion.AuthnStatement AuthnInstant: now_iso, SessionIndex: reference_string do |statement|
            statement.AuthnContext do |context|
              context.AuthnContextClassRef authn_context_classref
            end
          end
        end
      end
    end
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
      default_algorithm, # Sha256
      my_authn_context_classref,
      expiry,
      encryption_opts
    ).build

    REXML::Document.new(Base64.decode64(response)).write($stdout, 2) # write to stdout for easier logging
    puts # get the next rails logger on a new line

    render "idp-initiated-response", locals: { saml_acs_url: saml_acs_url, responseParams: { SAMLResponse: response } }
  end
end
