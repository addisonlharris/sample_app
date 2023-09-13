module SessionsHelper
  # logs in the given user
  def log_in(user)
    session[:user_id] = user.id
    #guard against session replay attacks
    #see https://bit.ly/33UvK0w for more.
    session[:session_token] = user.session_token
  end

  #remembers a user in a persistent session.
  def remember(user)
    user.remember
    cookies.permanent.encrypted[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end

  #returns the current logged-in user (if any).
  def current_user
    if (user_id = session[:user_id])
      user = User.find_by(id: user_id)
      if user && session[:session_token] == user.session_token
        @current_user = user
      end
    elsif (user_id = cookies.encrypted[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(:remember, cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end

  #returns true is the user is logged in, false otherwise
  def logged_in?
    !current_user.nil?
  end

  #forgets a persistent session.
  def forget(user)
    user.forget
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end

  #Logs out the current user.
  def log_out
    forget(current_user)
    reset_session
    @current_user = nil
  end
  #returns true if the given user is the current user.
  def current_user?(user)
    user && user == current_user
  end

  #stores the url trying to be accessed.
  def store_location
    session[:forwarding_url] = request.original_url if request.get?
  end
end