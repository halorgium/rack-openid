require 'test/unit'
require 'rack/openid'
require 'mocha'

class BeginAuthenticationTest < Test::Unit::TestCase
  OpenIDProvider = "http://www.myopenid.com/"

  def test_with_get
    stub_consumer! :request => lambda { |request|
      request.expects(:redirect_url).returns(OpenIDProvider)
    }

    app = app("identifier=loudthinking.com")
    response = process(app, "/", :method => :get)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
  end

  def test_with_post_method
    return_to_args = {}
    stub_consumer! :request => lambda { |request|
      request.expects(:return_to_args).returns(return_to_args)
      request.expects(:redirect_url).
        with('http://example.org', 'http://example.org/').
        returns(OpenIDProvider)
    }

    app = app("identifier=loudthinking.com")
    response = process(app, "/", :method => :post)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
    assert_equal({"_method" => "post"}, return_to_args)
  end

  def test_with_custom_return_to
    stub_consumer! :request => lambda { |request|
      request.expects(:redirect_url).
        with('http://example.org', '/complete').
        returns(OpenIDProvider)
    }

    app = app("identifier=loudthinking.com&return_to=/complete")
    response = process(app, "/", :method => :get)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
  end

  def test_with_post_method_custom_return_to
    stub_consumer! :request => lambda { |request|
      request.expects(:redirect_url).
        with('http://example.org', '/complete').
        returns(OpenIDProvider)
    }

    app = app("identifier=loudthinking.com&return_to=/complete")
    response = process(app, "/", :method => :post)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
  end

  def test_with_custom_return_method
    return_to_args = {}
    stub_consumer! :request => lambda { |request|
      request.expects(:return_to_args).returns(return_to_args)
      request.expects(:redirect_url).
        with('http://example.org', 'http://example.org/').
        returns(OpenIDProvider)
    }

    app = app("identifier=loudthinking.com&method=put")
    response = process(app, "/", :method => :get)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
    assert_equal({"_method" => "put"}, return_to_args)
  end

  def test_with_simple_registration_fields
    stub_consumer! :request => lambda { |request|
      request.expects(:redirect_url).returns(OpenIDProvider)
    }, :sregreq => lambda { |sreg|
      sreg.expects(:request_fields).with(["nickname", "email"], true)
      sreg.expects(:request_fields).with(["fullname"], false)
    }

    app = app("identifier=loudthinking.com&required=nickname&required=email&optional=fullname")
    response = process(app, "/", :method => :get)

    assert_equal 303, response.status
    assert_equal OpenIDProvider, response.headers["Location"]
  end

  def test_with_missing_id
    stub_consumer! :failure => true

    app = app("identifier=loudthinking.com")
    response = process(app, "/")

    assert_equal 400, response.status
    assert_equal "missing", response.body
  end

  def test_with_timeout
    stub_consumer! :timeout => true

    app = app("identifier=loudthinking.com")
    response = process(app, "/")

    assert_equal 400, response.status
    assert_equal "missing", response.body
  end

  private
    def app(qs)
      app = lambda { |env|
        if resp = env[Rack::OpenID::RESPONSE]
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
        if options[:sregreq]
          sregreq = mock()
          options[:sregreq].call(sregreq)
          OpenID::SReg::Request.expects(:new).returns(sregreq)
          request.expects(:add_extension).with(sregreq)
        else
          request.expects(:add_extension)
        end
        options[:request].call(request) if options[:request]
        consumer.expects(:begin).returns(request)
      end

      consumer
    end
end
