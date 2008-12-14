require 'test/unit'
require 'rack/openid'
require 'mocha'

class OpenIDTest < Test::Unit::TestCase
  def test_begin_authentication
    stub_consumer!

    app = app_needs_authentication "identifier=loudthinking.com"
    response = process(app, "/")

    assert_equal 303, response.status
    assert_match /www\.myopenid\.com/, response.headers["Location"]
  end

  def test_begin_authentication_with_missing_id
    stub_consumer! :failure => true

    app = app_needs_authentication "identifier=loudthinking.com"
    response = process(app, "/")

    assert_equal 400, response.status
    assert_equal "missing", response.body
  end

  def test_begin_authentication_with_timeout
    stub_consumer! :timeout => true

    app = app_needs_authentication "identifier=loudthinking.com"
    response = process(app, "/")

    assert_equal 400, response.status
    assert_equal "missing", response.body
  end

  private
    def app_needs_authentication(qs)
      app = lambda { |env|
        if resp = env["rack.auth.openid.response"]
          [400, {}, [resp.status.to_s]]
        else
          [401, {"X-OpenID-Authenticate" => qs}, []]
        end
      }
      wrap_app(app)
    end

    def wrap_app(app)
      Rack::Session::Pool.new(Rack::OpenID.new(app))
    end

    def process(app, *args)
      env = Rack::MockRequest.env_for(*args)
      Rack::MockResponse.new(*app.call(env))
    end

    def stub_consumer!(*args)
      OpenID::Consumer.expects(:new).returns(mock_consumer(*args))
    end

    def mock_consumer(options = {})
      consumer = mock()

      if options[:timeout]
        consumer.expects(:begin).raises(Timeout::Error,
          "Identity Server took too long.")
      elsif options[:failure]
        consumer.expects(:begin).raises(OpenID::OpenIDError)
      else
        request = mock()
        request.expects(:add_extension)
        url = "http://www.myopenid.com/"
        request.expects(:redirect_url).returns(url)
        consumer.expects(:begin).returns(request)
      end

      consumer
    end
end
