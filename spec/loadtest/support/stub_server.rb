require 'socket'
require 'uri'

# A minimal HTTP/1.1 server for testing the harness against real sockets.
#
# A fake transport (see flows_spec.rb) cannot exercise cookie handling, redirect
# following, form encoding, or timeouts, because those live in HttpClient itself.
# This server is the smallest thing that can: pure stdlib, one thread, one
# connection at a time, closing each connection so Net::HTTP does not block.
class StubServer
  Request = Struct.new(:method, :path, :headers, :body, keyword_init: true) do
    def cookie
      headers['cookie']
    end

    # @return [Hash] the form-encoded body as parameters
    def params
      URI.decode_www_form(body.to_s).to_h
    end
  end

  # @param handler [Proc] receives a Request, returns [status, headers, body]
  def initialize(&handler)
    @handler = handler
    @requests = []
    @mutex = Mutex.new
    @server = TCPServer.new('127.0.0.1', 0)
    @thread = Thread.new { serve }
  end

  def port
    @server.addr[1]
  end

  def base_url
    "http://127.0.0.1:#{port}"
  end

  def requests
    @mutex.synchronize { @requests.dup }
  end

  def shutdown
    @thread.kill
    @server.close
  rescue IOError
    nil
  end

  private

  def serve
    loop do
      socket = @server.accept
      begin
        request = read_request(socket)
        next if request.nil?

        @mutex.synchronize { @requests << request }
        status, headers, body = @handler.call(request)
        write_response(socket, status, headers, body)
      ensure
        socket.close
      end
    end
  rescue IOError, Errno::EBADF
    nil
  end

  def read_request(socket)
    request_line = socket.gets
    return nil if request_line.nil?

    method, path, = request_line.split(' ')
    headers = read_headers(socket)
    length = headers['content-length'].to_i
    body = length.positive? ? socket.read(length) : ''

    Request.new(method: method, path: path, headers: headers, body: body)
  end

  def read_headers(socket)
    headers = {}
    while (line = socket.gets) && line.strip != ''
      name, _, value = line.partition(':')
      headers[name.strip.downcase] = value.strip
    end
    headers
  end

  def write_response(socket, status, headers, body)
    socket.write("HTTP/1.1 #{status} OK\r\n")
    socket.write("Content-Length: #{body.bytesize}\r\n")
    socket.write("Connection: close\r\n")
    headers.each { |name, value| socket.write("#{name}: #{value}\r\n") }
    socket.write("\r\n")
    socket.write(body)
  end
end
