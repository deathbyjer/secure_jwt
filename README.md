# SecureJwt

Signed and encrypted JSON Web Tokens.

This library uses envelope encryption for transport of the contained data. 

This library was written to avoid exiting methods early in case of incorrect signatures or encryption information. This is done to mitigate timing attacks. (However, the library has not been battle tested against timing attack attempts.)

This library follows an encrypt-then-sign approach to doing encryption and signing. It also supports a wide variety of encryption mechanisms, but uses AES-256-GCM by default.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'secure_jwt'
```

## Usage


### With minimally protective encryption (should be used only for dev)

Encrypted, but unsigned, JWT's can be created in the following manner.

```ruby
jwt = SecureJwt.encrypt "foo"

SecureJwt.decrypt jwt
```

Encrypted and signed JWT's can be generated as follows.

```ruby
jwt = SecureJwt.encrypt "foo", "bar"

SecureJwt.decrypt jwt, "bar"
```

### Better Encryption

The above method uses the default key for encryption. This key will not provide any significant data security. You can significantly enhance your encryption scheme by using a more random key. This can be set as the `:master_key` in an option to the encryption and decryption function. (The reason for the name will be made clear a bit later)

This looks as following:

```ruby
jwt = SecureJwt.encrypt "foo", "bar", master_key: YOUR_VERY_RANDOM_MASTER_KEY

SecureJwt.decrypt jwt, "bar", master_key: YOUR_VERY_RANDOM_MASTER_KEY
```

You can also set this master key globally, if you wish as follows:

```ruby
SecureJwt.configs.master_key = A_STANDARD_MASTER_KEY
```

### Advanced / Envelope Encryption
A major purpose of envelope encryption is to take advantage of security hardware without also needing to send larger portions of data to the encryption hardware. A smaller data key is generated and used to symmetrically encrypt the main data and then that key is encrypted, often asymmetrically and using an HSM, and then sent along with the data. 

SecureJwt was built to support this type of encryption and to be flexible to allow one to take advantage key management systems of whatever service they are using (AWS, Google, etc).

Say we have a cloud encryption function `encrypt_with_key(key, value)` and a decryption function `decrypt_with_key(key, value)`, where the `key` represents the master key to our system and the `value` represents whatever it is we want to encrypt/decrypt. We can then approach it as follows:


```ruby
jwt = SecureJwt.encrypt("foo", "bar", master_key: MASTER_KEY) {|value,key| encrypt_with_key key, value }

SecureJwt.decrypt(jwt, "bar", master_key: MASTER_KEY) { |value, key| decrypt_with_key key, value }
```

And that's it. Simple as that.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/deathbyjer/secure_jwt. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the SecureJwt project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/secure_jwt/blob/master/CODE_OF_CONDUCT.md).
