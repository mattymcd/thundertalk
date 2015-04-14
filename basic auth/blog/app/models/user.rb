class User < ActiveRecord::Base
  attr_accessor :password
  validates_confirmation_of :password
  before_save :encrypt_password

  def encrypt_password
    self.password_salt = BCrypt::Engine.generate_salt
    self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
  end

  def self.authenticate(email, password)
    user = User.where(email: email).first
    if user && user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
      user
    else
      nil
    end

# What this does
# Given an email and password
# Lookup a user in the database
# If a user is found
# Hash the password with that user’s salt using the same bcrypt method we used originally to hash the user’s password
# If the hashed password matches with what is stored in the database, return the user’s object
# If it does not match, return nil

  end

end
