require "secure_jwt"
require "base64"

RSpec.describe SecureJwt do 

  it "will encrypt and sign, even without details" do
    jwt = SecureJwt.encrypt "foo"
    expect(SecureJwt.decrypt(jwt)).to eq("foo")
  end

  context "signing" do
    it "will sign with a given key" do
      without_key = SecureJwt.encrypt "foo"
      with_key = SecureJwt.encrypt "foo", "bar"
      expect(with_key).not_to eq(without_key)
    end

    it "will succeed with matching keys" do
      jwt = SecureJwt.encrypt "foo", "bar"
      expect(SecureJwt.decrypt(jwt, "bar")).to eq("foo")
    end

    it "will fail if mismatched signing key" do
      jwt = SecureJwt.encrypt "foo", "bar"
      expect { SecureJwt.decrypt jwt, "barbar" }.to raise_error(JWT::VerificationError)
    end

    it "will work with another signing algorithm" do
      jwt = SecureJwt.encrypt "foo", "bar", signing_algorithm: "HS512"
      expect(SecureJwt.decrypt(jwt, "bar", signing_algorithm: "HS512")).to eq("foo") 
    end

    it "will not work with mismatched signing algorithms" do
      jwt = SecureJwt.encrypt "foo", "bar", signing_algorithm: "HS384"
      expect { SecureJwt.decrypt jwt, "barbar" }.to raise_error(JWT::IncorrectAlgorithm)


      jwt = SecureJwt.encrypt "foo", "bar", signing_algorithm: "HS384"
      expect { SecureJwt.decrypt jwt, "barbar" }.to raise_error(JWT::IncorrectAlgorithm)
    end
  end

  context "expiration" do
    it "expires" do
      jwt = SecureJwt.encrypt "foo", "bar", expires: Time.now - 60
      expect {SecureJwt.decrypt(jwt, "bar")}.to raise_error(JWT::ExpiredSignature)
    end
  end

  context "configs" do
    after(:each) { SecureJwt.config.send(:clear!) }

    it "globally sets master key" do
      expect(SecureJwt.config.master_key).not_to eq("hey")
      SecureJwt.config.master_key = "hey"
      expect(SecureJwt.config.master_key).to eq("hey")
    end
  end

  context "simple encryption" do
    after(:each) { SecureJwt.config.send(:clear!) }

    it "will encrypt with matching master keys" do
      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar"
      expect(SecureJwt.decrypt(jwt, "bar", master_key: "foobar")).to eq("foo")
    end

    it "will fail with different master keys" do
      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar"
      expect { SecureJwt.decrypt(jwt, "bar", master_key: "foobar2")}.to raise_error(OpenSSL::Cipher::CipherError)
    end

    it "will use a globally set master key" do
      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar2"

      SecureJwt.config.master_key = "foobar2"
      expect(SecureJwt.decrypt(jwt, "bar")).to eq("foo")
    end

    it "will override a globally set master key" do
      SecureJwt.config.master_key = "foobar2"

      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar"
      expect(SecureJwt.decrypt(jwt, "bar", master_key: "foobar")).to eq("foo")
    end

    it "will fail if encrypted with a different key than the global master" do
      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar"
      
      SecureJwt.config.master_key = "foobar2"
      expect { SecureJwt.decrypt(jwt, "bar")}.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end

  context "encrypting with custom key encryptors" do
    def encrypt(value, key)
      cipher = OpenSSL::Cipher.new "aes-256-cbc"
      cipher.encrypt

      cipher.key = Digest::SHA2.digest key
      cipher.iv = Digest::MD5.digest key
      cipher.update(value) + cipher.final
    end

    def decrypt(encrypted, key)
      cipher = OpenSSL::Cipher.new "aes-256-cbc"
      cipher.decrypt

      cipher.key = Digest::SHA2.digest key
      cipher.iv = Digest::MD5.digest key
      cipher.update(encrypted) + cipher.final
    end

    def decrypt_2(value, key)
      cipher = OpenSSL::Cipher.new "aes-256-cbc"
      cipher.decrypt

      cipher.key = Digest::SHA2.digest key
      cipher.iv = Digest::MD5.digest "standard_iv"
      cipher.update(encrypted) + cipher.final
    end

    def encrypt_with_iv(value, key)
      cipher = OpenSSL::Cipher.new "aes-256-cbc"
      cipher.encrypt

      cipher.key = Digest::SHA2.digest key
      cipher.iv = iv = cipher.random_iv
      encrypted = cipher.update(value) + cipher.final
      [Base64.encode64(encrypted), Base64.encode64(iv)].join("::")
    end

    def decrypt_with_iv(encrypted, key)
      encrypted, iv = encrypted.split("::")

      encrypted = Base64.decode64 encrypted
      iv = Base64.decode64 iv

      cipher = OpenSSL::Cipher.new "aes-256-cbc"
      cipher.decrypt

      cipher.key = Digest::SHA2.digest key
      cipher.iv = iv
      cipher.update(encrypted) + cipher.final
    end

    it "allows for a custom key hash" do
      jwt = SecureJwt.encrypt("foo", "bar") {|value, key| encrypt(value, key)}
      val = SecureJwt.decrypt(jwt, "bar") {|value, key| decrypt(value, key)}
      expect(val).to eq "foo"
    end

    it "will fail with different master keys" do
      jwt = SecureJwt.encrypt "foo", "bar", master_key: "foobar"
      expect { SecureJwt.decrypt(jwt, "bar") {|value, key| decrypt2(value, key)}}.to raise_error(OpenSSL::Cipher::CipherError)
    end

    it "can handle more complex blocks" do
      jwt = SecureJwt.encrypt("foo", "bar") {|value, key| encrypt_with_iv(value, key)}
      val = SecureJwt.decrypt(jwt, "bar") {|value, key| decrypt_with_iv(value, key)}
      expect(val).to eq "foo"
    end
  end
end