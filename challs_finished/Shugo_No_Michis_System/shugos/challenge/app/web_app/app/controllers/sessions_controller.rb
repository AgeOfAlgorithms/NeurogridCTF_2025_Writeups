class SessionsController < ApplicationController
  def new
    redirect_to root_path
  end

  def create
    user = User.find_by("LOWER(email) = ?", params[:email].to_s.downcase)
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      redirect_to root_path, notice: "Signed in."
    else
      @user = User.new  # so the Register form on home still works
      flash.now[:alert] = "Invalid email or password."
      render "home/index", status: :unprocessable_entity
    end
  end

  def destroy
    session.delete(:user_id)
    redirect_to root_path, notice: "Signed out."
  end
end
