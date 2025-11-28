class UsersController < ApplicationController
  protect_from_forgery unless: -> { request.format.json? }

  def new
    redirect_to root_path
  end

  def create
    @user = User.new(user_params)

    if @user.save
      session[:user_id] = @user.id
      redirect_to root_path, notice: "Welcome, you're signed in."
    else
      flash.now[:alert] = @user.errors.full_messages.to_sentence
      render "home/index", status: :unprocessable_entity
    end
  end

  private

  def user_params
    base = [:email, :password, :password_confirmation]
    extras = (request.format.json? || request.headers['Accept'].to_s.include?('json')) ? [:role] : []
    params.require(:user).permit(*(base + extras))
  end
end
