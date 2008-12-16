require 'rubygems'
require 'rack'

gem 'ruby-openid', '>=2.1.2'
require 'openid'
require 'openid/consumer'
require 'openid/extensions/sreg'
require 'openid/store/memory'

module Rack
  class OpenID
    def self.build_header(params = {})
      value = 'OpenID '
      value += params.map { |k, v|
        if v.is_a?(Array)
          "#{k}=\"#{v.join(',')}\""
        else
          "#{k}=\"#{v}\""
        end
      }.join(', ')
      value
    end

    def self.parse_header(str)
      params = {}
      if str =~ /^OpenID/
        str = str.gsub(/^OpenID /, '')
        str.split(', ').each { |e|
          k, v = e.split('=')
          v.gsub!(/^\"/, '').gsub!(/\"$/, "")
          v = v.split(',')
          params[k] = v.length > 1 ? v : v.first
        }
      end
      params
    end

    class TimeoutResponse
      include ::OpenID::Consumer::Response
      STATUS = :failure
    end

    class MissingResponse
      include ::OpenID::Consumer::Response
      STATUS = :missing
    end

    HTTP_METHODS = %w(GET HEAD PUT POST DELETE OPTIONS)

    RESPONSE = "rack.openid.response".freeze
    AUTHENTICATE_HEADER = "WWW-Authenticate".freeze


    def initialize(app, store = nil)
      @app = app
      @store = store || ::OpenID::Store::Memory.new
      freeze
    end

    def call(env)
      req = Rack::Request.new(env)
      if env["REQUEST_METHOD"] == "GET" && req.GET["openid.mode"]
        complete_authentication(env)
      end

      status, headers, body = @app.call(env)

      if status.to_i == 401 && (qs = headers[AUTHENTICATE_HEADER])
        begin_authentication(env, qs)
      else
        [status, headers, body]
      end
    end

    private
      def begin_authentication(env, qs)
        req = Rack::Request.new(env)
        params = self.class.parse_header(qs)

        unless session = env["rack.session"]
          raise RuntimeError, "Rack::OpenID requires a session"
        end

        consumer = ::OpenID::Consumer.new(session, @store)
        identifier = params["identifier"]

        begin
          oidreq = consumer.begin(identifier)
          add_simple_registration_fields(oidreq, params)
          url = open_id_redirect_url(req, oidreq, params["return_to"], params["method"])
          return redirect_to(url)
        rescue ::OpenID::OpenIDError, Timeout::Error => e
          env[RESPONSE] = MissingResponse.new
          return self.call(env)
        end
      end

      def complete_authentication(env)
        req = Rack::Request.new(env)

        unless session = env["rack.session"]
          raise RuntimeError, "Rack::OpenID requires a session"
        end

        oidresp = timeout_protection_from_identity_server {
          consumer = ::OpenID::Consumer.new(session, @store)
          consumer.complete(req.params, req.url)
        }

        env[RESPONSE] = oidresp

        if method = req.GET["_method"]
          method = method.upcase
          if HTTP_METHODS.include?(method)
            env["REQUEST_METHOD"] = method
          end
        end

        query_hash = env["rack.request.query_hash"]
        query_hash.delete("_method")
        query_hash.delete_if do |key, value|
          key =~ /^openid\./
        end

        env["QUERY_STRING"] = env["rack.request.query_string"] =
          Rack::Utils.build_query(env["rack.request.query_hash"])

        request_uri = env["PATH_INFO"]
        if env["QUERY_STRING"].any?
          request_uri << "?" + env["QUERY_STRING"]
        end
        env["REQUEST_URI"] = request_uri
      end

      def realm_url(req)
        url = req.scheme + "://"
        url << req.host

        if req.scheme == "https" && req.port != 443 ||
            req.scheme == "http" && req.port != 80
          url << ":#{req.port}"
        end

        url
      end

      def request_url(req)
        url = realm_url(req)
        url << req.script_name
        url << req.path_info
        url
      end

      def redirect_to(url)
        [303, {"Content-Type" => "text/html", "Location" => url}, []]
      end

      def open_id_redirect_url(req, oidreq, return_to = nil, method = nil)
        if return_to
          method ||= "get"
        else
          return_to = request_url(req)
          method ||= req.request_method
        end

        method = method.to_s.downcase
        oidreq.return_to_args['_method'] = method unless method == "get"
        oidreq.redirect_url(realm_url(req), return_to)
      end

      def add_simple_registration_fields(oidreq, fields)
        sregreq = ::OpenID::SReg::Request.new

        if required = fields["required"]
          sregreq.request_fields(Array(required), true)
        end

        if optional = fields["optional"]
          sregreq.request_fields(Array(optional), false)
        end

        if policy_url = fields["policy_url"]
          sregreq.policy_url = policy_url
        end

        oidreq.add_extension(sregreq)
      end

      def timeout_protection_from_identity_server
        yield
      rescue Timeout::Error
        TimeoutResponse.new
      end
  end
end
