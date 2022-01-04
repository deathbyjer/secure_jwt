require "securerandom"
require 'openssl'
require "base64"
require "jwt"

require "secure_jwt/version"
require "secure_jwt/configs"

module SecureJwt

  extend SecureJwt::Configs

  DEFAULT_ALGORITHMS = {
    jwt: "HS256",
    data: "aes-256-gcm"
  }

  class << self
    def encrypt(payload, signing_key = nil, options = {}, &data_key_encryptor)
      secure_jwt = JwtTokenImpl.new signing_key, options
      secure_jwt.encrypt payload, options, &data_key_encryptor
    end

    def decrypt(jwt_token, signing_key = nil, options = {}, &data_key_decryptor)
      secure_jwt = JwtTokenImpl.new signing_key, options
      secure_jwt.decrypt jwt_token, options, &data_key_decryptor
    end
  end

  class JwtTokenImpl
    def initialize(signing_key, options = {})
      @jwt_algorithm = options[:signing_algorithm] || DEFAULT_ALGORITHMS[:jwt]
      @jwt_algorithm = "none" unless signing_key

      @signing_key = signing_key || nil

      @data_algorithm = options[:data_algorithm] || DEFAULT_ALGORITHMS[:data]

      @master_key = options[:master_key] || SecureJwt.config.master_key || "none"
      @include_master_key = options[:include_master_key] || false
    end

    def encrypt(payload, options = {}, &data_key_encryptor)
      clear!

      data_key = generate_data_key &data_key_encryptor
      iv = SecureRandom.random_bytes 12
      encrypted_payload, auth_tag = encrypt_payload payload, {
        key: data_key[:plain], 
        iv: iv,
        auth_data: options[:auth_data] || ""
      }

      ret = encode_jwt encrypted_payload, {
        data_key: data_key[:encrypted],
        iv: iv,
        auth_tag: auth_tag,
        expires: options[:expires]&.to_i
      }

      first_error ? raise(first_error) : ret
    end

    def decrypt(jwt_token, options = {}, &data_key_decryptor)
      clear!
      unformatted_payload, header = decode_jwt jwt_token

      decrypted_data_key = decrypt_data_key header[:data_key], &data_key_decryptor rescue SecureRandom.random_bytes(12)
      
      ret = decrypt_payload unformatted_payload, {
        data_key: decrypted_data_key,
        iv: header[:iv],
        auth_tag: header[:tag],
        auth_data: options[:auth_data] || ""
      }

      first_error ? raise(first_error) : ret
    end

    private

    attr_reader :signing_key
    attr_reader :jwt_algorithm
    attr_reader :data_algorithm
    attr_reader :master_key
    attr_reader :include_master_key

    attr_reader :first_error

    def clear!
      @first_error = nil
    end

    def encode_jwt(encrypted_payload, options = {})
      headers = { 
        data_key: Base64.urlsafe_encode64(options[:data_key]), 
        iv: Base64.urlsafe_encode64(options[:iv]),
      }

      headers[:master_key] = master_key if include_master_key

      headers[:tag] = Base64.urlsafe_encode64(options[:auth_tag]) if options[:auth_tag]

      formatted_payload = { 
        "data" => Base64.urlsafe_encode64(encrypted_payload),
        "exp" => options[:expires]
      }.compact

      JWT.encode formatted_payload, signing_key, jwt_algorithm, headers 
    end

    def decode_jwt(jwt_token)
      begin
        payload, header = JWT.decode jwt_token, signing_key, jwt_algorithm != "none", algorithm: jwt_algorithm, verify_expiration: true

        %w(data_key iv tag).each do |key| 
          header[key] = Base64.urlsafe_decode64 header[key] rescue ""
        end

        return Base64.urlsafe_decode64(payload["data"]), header.transform_keys(&:to_sym)
      rescue JWT::VerificationError, JWT::IncorrectAlgorithm => e
        self.first_error = e
        return {"data": nil}, { }
      end
    end

    def encrypt_payload(payload, options = {})
      cipher = OpenSSL::Cipher.new data_algorithm
      cipher.encrypt

      begin
        cipher.key = options[:key]
        cipher.iv = options[:iv]
        cipher.auth_data = options[:auth_data] if cipher.authenticated?

        encrypted_payload = cipher.update(payload) + cipher.final

        return encrypted_payload, cipher.authenticated? ? cipher.auth_tag : nil
      rescue Exception => e
        self.first_error = e
        return "", cipher.authenticated? ? "" : nil
      end
    end

    def decrypt_payload(unformatted_payload, options = {})
      begin
        cipher = OpenSSL::Cipher.new data_algorithm
        cipher.decrypt

        cipher.key = options[:data_key] || cipher.random_key
        cipher.iv = options[:iv]

        if cipher.authenticated?
          cipher.auth_tag = options[:auth_tag]
          cipher.auth_data = options[:auth_data]
        end

        return cipher.update(unformatted_payload) + cipher.final
      rescue Exception => e
        self.first_error = e
        nil
      end
    end

    def generate_data_key(&block)
      plain_key = SecureRandom.random_bytes 32

      encrypted_key = block ? block.call(plain_key, master_key) : default_data_key_encryptor(plain_key)

      { plain: plain_key, encrypted: encrypted_key, key: master_key }
    end

    def decrypt_data_key(encrypted_key, &block)
      data_key = block ? block.call(encrypted_key, master_key) : default_data_key_decryptor(encrypted_key) rescue nil
      return data_key unless data_key.nil? 

      self.first_error = OpenSSL::Cipher::CipherError.new("bad decrypt") 
      nil
    end

    DEFAULT_KEY_ALGORITHM = "aes-256-cbc"
    def default_data_key_encryptor(plain_key)
      cipher = OpenSSL::Cipher.new DEFAULT_KEY_ALGORITHM
      cipher.encrypt

      cipher.key = Digest::SHA2.digest "key:#{master_key}"
      cipher.iv = Digest::MD5.digest "iv:#{master_key}"
      cipher.update(plain_key) + cipher.final
    end

    def default_data_key_decryptor(encrypted_key)
      cipher = OpenSSL::Cipher.new DEFAULT_KEY_ALGORITHM
      cipher.decrypt
      
      cipher.key = Digest::SHA2.digest "key:#{master_key || "none"}"
      cipher.iv = Digest::MD5.digest "iv:#{master_key || "none"}"
      cipher.update(encrypted_key) + cipher.final
    end

    def first_error=(error)
      return if @first_error
      @first_error = error
    end
  end
end
