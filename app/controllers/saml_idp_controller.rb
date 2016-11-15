class User
  attr_reader :email, :password
  def initialize(email:, password:)
    @email = email
    @password = password 
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
    Digest::MD5.hexdigest(email)
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


class SamlIdpController < SamlIdp::IdpController

  def idp_authenticate(email, password) # not using params intentionally
    user = User.new(email: email, password: password)
    user && user.valid_password? ? user : nil
  end
  private :idp_authenticate

  def idp_make_saml_response(found_user) # not using params intentionally
    # NOTE encryption is optional
    encode_response found_user#, encryption: {
#      cert: saml_request.service_provider.cert,
#      block_encryption: 'aes256-cbc',
#      key_transport: 'rsa-oaep-mgf1p'
#    }
  end
  private :idp_make_saml_response

  def idp_logout
    true # mimic logout
  end
  private :idp_logout
end
