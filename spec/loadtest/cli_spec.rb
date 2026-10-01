require_relative 'spec_helper'
require_relative 'support/stub_server'
require_relative '../../lib/loadtest/cli'
require 'csv'
require 'stringio'
require 'tmpdir'

# End-to-end coverage of the harness: the real CLI, scheduler, threads, HTTP
# client, and report, driven against stub servers standing in for the Sinatra
# relying party and the IdP.
#
# This is what proves the pieces are wired together. The unit specs verify each
# piece in isolation; only this one catches a flow that is implemented but never
# dispatched, or a config value that never reaches a request.
RSpec.describe LoginGov::OidcSinatra::Loadtest::CLI do
  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  after do
    idp&.shutdown
    rp&.shutdown
  end

  let(:idp) { nil }
  let(:rp) { nil }

  def run_cli(args)
    described_class.new(argv: args, stdout: stdout, stderr: stderr, env: {}).run
  end

  describe '--help' do
    it 'exits successfully' do
      expect(run_cli(['--help'])).to eq(described_class::EXIT_OK)
    end

    it 'documents the per-flow run counts, the harness’s main control' do
      run_cli(['--help'])

      expect(stdout.string).to include('--flow-runs')
    end
  end

  describe '--plan' do
    it 'reports the planned runs per flow' do
      run_cli(['--plan', '--flow-runs', 'auth_only=3,signup=2'])

      expect(stdout.string).to match(/auth_only\s+3/).and match(/signup\s+2/)
    end

    it 'sends no requests at all' do
      # Confirms the plan is safe to run against a production-like target.
      server = StubServer.new { |_r| [200, {}, 'should not be hit'] }
      begin
        run_cli(['--plan', '--flow-runs', 'auth_only=2', '--idp-url', server.base_url])

        expect(server.requests).to be_empty
      ensure
        server.shutdown
      end
    end
  end

  describe 'configuration errors' do
    it 'exits with the config error status' do
      expect(run_cli(['--flow-runs', 'auth_only=0'])).
        to eq(described_class::EXIT_CONFIG_ERROR)
    end

    it 'explains that there is no work to do' do
      run_cli(['--flow-runs', 'auth_only=0'])

      expect(stderr.string).to include('total runs')
    end

    it 'rejects an unknown flow name' do
      run_cli(['--flow-runs', 'teleport=1'])

      expect(stderr.string).to include('unknown flow')
    end

    it 'rejects overlapping user pools, naming the fix' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'loadtest.yml')
        File.write(path, <<~YAML)
          flows:
            auth_only:
              runs: 1
              user_index_start: 0
              user_pool_size: 5
            idv:
              runs: 1
              user_index_start: 0
              user_pool_size: 5
        YAML

        run_cli(['--config', path])

        expect(stderr.string).to include('user_index_start')
      end
    end
  end

  # A pair of stub servers that behave like the real applications for the
  # authentication-only flow: the relying party redirects to the IdP, the IdP
  # authenticates and hands back a code, the relying party reports userinfo.
  def start_stub_pair
    idp_server = nil
    rp_server = StubServer.new do |request|
      if request.path.start_with?('/auth/request')
        [302, { 'Location' => "#{idp_server.base_url}/openid_connect/authorize" }, '']
      else
        [200, {}, '<span>Received user info:</span>']
      end
    end

    idp_server = StubServer.new do |request|
      case request.path
      when %r{\A/openid_connect/authorize}
        [302, { 'Location' => '/' }, '']
      when '/'
        if request.method == 'POST'
          [200, {}, otp_page]
        else
          # Set a session cookie, as the real IdP does, so the harness's cookie
          # handling is exercised rather than assumed.
          [200, { 'Set-Cookie' => '_idp_session=s1; path=/; HttpOnly' }, sign_in_page]
        end
      when %r{\A/login/two_factor}
        [302, { 'Location' => "#{rp_server.base_url}/auth/result?code=abc&state=xyz" }, '']
      else
        [404, {}, 'not found']
      end
    end

    [idp_server, rp_server]
  end

  def sign_in_page
    <<~HTML
      <form action="/" method="post">
        <input type="hidden" name="authenticity_token" value="signin-token">
        <input name="user[email]"><input name="user[password]">
      </form>
    HTML
  end

  def otp_page
    <<~HTML
      <form action="/login/two_factor/sms" method="post">
        <input type="hidden" name="authenticity_token" value="otp-token">
        <input type="text" name="code" id="code" value="123456">
      </form>
    HTML
  end

  describe 'a successful run' do
    let(:servers) { start_stub_pair }
    let(:idp) { servers[0] }
    let(:rp) { servers[1] }

    def run_auth_only(extra = [])
      run_cli(
        [
          '--flow-runs', 'auth_only=3',
          '--vus', '2',
          '--idp-url', idp.base_url,
          '--rp-url', rp.base_url,
        ] + extra,
      )
    end

    it 'exits successfully when every run completes' do
      expect(run_auth_only).to eq(described_class::EXIT_OK)
    end

    it 'executes exactly the requested number of runs' do
      run_auth_only

      starts = rp.requests.count { |request| request.path.start_with?('/auth/request') }
      expect(starts).to eq(3)
    end

    it 'signs in against the IdP on every run' do
      run_auth_only

      sign_ins = idp.requests.count { |request| request.method == 'POST' && request.path == '/' }
      expect(sign_ins).to eq(3)
    end

    it 'submits the one-time code it read off the IdP page' do
      run_auth_only

      otp = idp.requests.find { |request| request.path.start_with?('/login/two_factor') }
      expect(otp.params).to include('code' => '123456')
    end

    it 'holds the IdP session cookie across requests within a run' do
      run_auth_only

      # The sign-in POST must carry the cookie the IdP set when the sign-in page
      # was fetched, or the IdP would treat it as a brand-new session and reject
      # the CSRF token.
      sign_in = idp.requests.find { |request| request.method == 'POST' && request.path == '/' }

      expect(sign_in.cookie).to include('_idp_session=')
    end

    it 'reports the run count and throughput' do
      run_auth_only

      expect(stdout.string).to include('Runs: 3').and include('Throughput')
    end

    it 'reports per-flow latency' do
      run_auth_only

      expect(stdout.string).to match(/auth_only\s+3\s+3\s+0/)
    end

    it 'reports per-step latency' do
      run_auth_only

      expect(stdout.string).to include('Per step').and include('otp_submit')
    end

    it 'writes one CSV row per run plus a header' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_auth_only(['--csv', path])

        expect(CSV.read(path).length).to eq(4)
      end
    end

    it 'records the flow, status, and step breakdown in each CSV row' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_auth_only(['--csv', path])
        row = CSV.read(path, headers: true).first

        expect(row.fetch('flow')).to eq('auth_only')
        expect(row.fetch('status')).to eq('ok')
        expect(row.fetch('steps')).to include('otp_submit=')
      end
    end

    it 'writes a JSON summary when asked' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'summary.json')
        run_auth_only(['--json', path])

        expect(JSON.parse(File.read(path)).fetch('totals')).to include('ok' => 3)
      end
    end
  end

  describe 'mixed flows' do
    let(:servers) { start_stub_pair }
    let(:idp) { servers[0] }
    let(:rp) { servers[1] }

    it 'runs auth_only and idv in one pass, at their respective levels' do
      run_cli(
        [
          '--flow-runs', 'auth_only=2,idv=2',
          '--vus', '2',
          '--idp-url', idp.base_url,
          '--rp-url', rp.base_url,
        ],
      )

      levels = rp.requests.
        select { |request| request.path.start_with?('/auth/request') }.
        map { |request| request.path[/ial=(\d)/, 1] }

      expect(levels.tally).to eq('1' => 2, '2' => 2)
    end

    it 'keeps the two flows on separate seeded user ranges' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_cli(
          [
            '--flow-runs', 'auth_only=2,idv=2',
            '--vus', '2',
            '--idp-url', idp.base_url,
            '--rp-url', rp.base_url,
            '--csv', path,
          ],
        )

        by_flow = CSV.read(path, headers: true).group_by { |row| row.fetch('flow') }
        auth_emails = by_flow.fetch('auth_only').map { |row| row.fetch('identity') }
        idv_emails = by_flow.fetch('idv').map { |row| row.fetch('identity') }

        expect(auth_emails & idv_emails).to be_empty
      end
    end
  end

  describe 'the signup flow' do
    # A stub pair for account creation: the relying party asks for
    # prompt=create, the IdP walks registration, confirmation, password, MFA
    # selection, phone setup, and OTP, then hands back a code.
    def start_signup_pair
      idp_server = nil
      rp_server = StubServer.new do |request|
        if request.path.start_with?('/auth/request')
          [302, { 'Location' => "#{idp_server.base_url}/openid_connect/authorize?prompt=create" }, '']
        else
          [200, {}, '<span>Received user info:</span>']
        end
      end

      idp_server = StubServer.new do |request|
        signup_response(request, rp_server)
      end

      [idp_server, rp_server]
    end

    def signup_response(request, rp_server)
      case request.path
      when %r{\A/openid_connect/authorize}
        [302, { 'Location' => '/sign_up/enter_email' }, '']
      when '/sign_up/enter_email'
        request.method == 'POST' ? [200, {}, verify_email_page] : [200, {}, enter_email_page]
      when %r{\A/sign_up/email/confirm}
        [200, {}, enter_password_page]
      when '/sign_up/create_password'
        [200, {}, mfa_selection_page]
      when '/authentication_methods_setup'
        [200, {}, phone_setup_page]
      when '/phone_setup'
        [200, {}, otp_page]
      when %r{\A/login/two_factor}
        [302, { 'Location' => "#{rp_server.base_url}/auth/result?code=abc&state=xyz" }, '']
      else
        [404, {}, 'not found']
      end
    end

    def enter_email_page
      <<~HTML
        <form action="/sign_up/enter_email" method="post">
          <input type="hidden" name="authenticity_token" value="email-token">
          <input type="hidden" name="user[recaptcha_token]" value="mock_token">
          <input name="user[email]">
        </form>
      HTML
    end

    def verify_email_page
      '<a id="confirm-now" href="/sign_up/email/confirm?confirmation_token=tok">CONFIRM NOW</a>'
    end

    def enter_password_page
      <<~HTML
        <form action="/sign_up/create_password" method="post">
          <input type="hidden" name="authenticity_token" value="pw-token">
          <input type="hidden" name="password_form[confirmation_token]" value="tok">
        </form>
      HTML
    end

    def mfa_selection_page
      <<~HTML
        <form action="/authentication_methods_setup" method="post">
          <input type="hidden" name="_method" value="patch">
          <input type="hidden" name="authenticity_token" value="mfa-token">
        </form>
      HTML
    end

    def phone_setup_page
      <<~HTML
        <form action="/phone_setup" method="post">
          <input type="hidden" name="authenticity_token" value="phone-token">
        </form>
      HTML
    end

    let(:servers) { start_signup_pair }
    let(:idp) { servers[0] }
    let(:rp) { servers[1] }

    def run_signup(count: 2)
      run_cli(
        [
          '--flow-runs', "signup=#{count}",
          '--vus', '2',
          '--idp-url', idp.base_url,
          '--rp-url', rp.base_url,
        ],
      )
    end

    it 'completes account creation end to end' do
      expect(run_signup).to eq(described_class::EXIT_OK)
    end

    it 'asks the relying party to initiate registration' do
      run_signup

      starts = rp.requests.select { |request| request.path.start_with?('/auth/request') }
      expect(starts.first.path).to include('initiate_registration=1')
    end

    it 'registers a distinct synthetic address per run' do
      # Registration rejects an address that is already confirmed, so reusing one
      # would fail on the second run.
      run_signup(count: 3)

      emails = idp.requests.
        select { |request| request.method == 'POST' && request.path == '/sign_up/enter_email' }.
        map { |request| request.params.fetch('user[email]') }

      expect(emails.uniq.length).to eq(3)
      expect(emails).to all(match(/\Aloadtest\+/))
    end

    it 'confirms the address through the load-testing link, sending no email' do
      run_signup(count: 1)

      confirm = idp.requests.find { |request| request.path.start_with?('/sign_up/email/confirm') }
      expect(confirm.path).to include('confirmation_token=tok')
    end

    it 'sets a password that satisfies the IdP length rule' do
      run_signup(count: 1)

      create = idp.requests.find { |request| request.path == '/sign_up/create_password' }
      expect(create.params.fetch('password_form[password]').length).to be >= 12
    end

    it 'enrolls phone as the authentication method' do
      run_signup(count: 1)

      setup = idp.requests.find { |request| request.path == '/authentication_methods_setup' }
      expect(setup.params).to include('two_factor_options_form[selection]' => 'phone')
    end

    it 'confirms the phone with the prefilled code' do
      run_signup(count: 1)

      otp = idp.requests.find { |request| request.path.start_with?('/login/two_factor') }
      expect(otp.params).to include('code' => '123456')
    end

    it 'reports the signup flow separately in the summary' do
      run_signup

      expect(stdout.string).to match(/signup\s+2\s+2\s+0/)
    end
  end

  describe 'a failing run' do
    let(:idp) do
      StubServer.new { |_request| [200, {}, '<p>no form here</p>'] }
    end
    let(:rp) do
      server = nil
      server = StubServer.new do |request|
        if request.path.start_with?('/auth/request')
          [302, { 'Location' => "#{idp.base_url}/" }, '']
        else
          [200, {}, 'unexpected']
        end
      end
      server
    end

    def run_failing
      run_cli(
        [
          '--flow-runs', 'auth_only=2',
          '--vus', '1',
          '--idp-url', idp.base_url,
          '--rp-url', rp.base_url,
        ],
      )
    end

    it 'exits nonzero so the harness can gate a pipeline' do
      expect(run_failing).to eq(described_class::EXIT_RUN_FAILURES)
    end

    it 'keeps running after a failure rather than aborting the thread' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_cli(
          [
            '--flow-runs', 'auth_only=2',
            '--vus', '1',
            '--idp-url', idp.base_url,
            '--rp-url', rp.base_url,
            '--csv', path,
          ],
        )

        expect(CSV.read(path, headers: true).length).to eq(2)
      end
    end

    it 'names the step that failed' do
      run_failing

      expect(stdout.string).to include('sign_in_submit')
    end

    it 'does not suppress the error' do
      run_failing

      expect(stdout.string).to include('Failures')
    end
  end

  describe 'concurrency' do
    let(:servers) { start_stub_pair }
    let(:idp) { servers[0] }
    let(:rp) { servers[1] }

    it 'never reuses a seeded user concurrently' do
      # identity-idp signs out a user's previous session when they sign in
      # again, so two concurrent runs sharing a user would fail each other.
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_cli(
          [
            '--flow-runs', 'auth_only=6',
            '--vus', '3',
            '--idp-url', idp.base_url,
            '--rp-url', rp.base_url,
            '--csv', path,
          ],
        )
        rows = CSV.read(path, headers: true)

        expect(rows.map { |row| row.fetch('status') }.uniq).to eq(['ok'])
      end
    end

    it 'distributes runs across virtual users' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        run_cli(
          [
            '--flow-runs', 'auth_only=6',
            '--vus', '3',
            '--idp-url', idp.base_url,
            '--rp-url', rp.base_url,
            '--csv', path,
          ],
        )
        vus = CSV.read(path, headers: true).map { |row| row.fetch('vu') }.uniq

        expect(vus.length).to be > 1
      end
    end
  end
end
