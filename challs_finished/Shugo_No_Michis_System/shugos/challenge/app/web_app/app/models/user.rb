class User < ApplicationRecord
  has_secure_password

  NORMALIZED_EMAIL = /\A[^@\s]+@[^@\s]+\z/
  ROLES = %w[admin user].freeze

  validates :email,
            presence: true,
            format:   { with: NORMALIZED_EMAIL },
            uniqueness: { case_sensitive: false }

  # validate length only when creating or when a password was provided
  validates :password,
            length: { minimum: 8 },
            if: -> { new_record? || password.present? }

  validates :role, presence: true, inclusion: { in: ROLES }
end
