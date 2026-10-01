require_relative 'spec_helper'
require_relative '../../lib/loadtest/page'

RSpec.describe LoginGov::OidcSinatra::Loadtest::Page do
  # These fixtures mirror the structure of the real identity-idp views that the
  # harness scrapes. They are intentionally reduced to the elements the harness
  # depends on, so a failure here points at a specific scraping assumption.

  describe '.csrf_token' do
    it 'returns the authenticity_token value' do
      html = <<~HTML
        <form action="/" method="post">
          <input type="hidden" name="authenticity_token" value="token-abc">
        </form>
      HTML

      expect(described_class.csrf_token(html)).to eq('token-abc')
    end

    it 'picks the token belonging to the requested form action' do
      # Rails is configured with per_form_csrf_tokens, so tokens are not
      # interchangeable between forms on the same page.
      html = <<~HTML
        <form action="/sign_up/enter_email" method="post">
          <input type="hidden" name="authenticity_token" value="email-token">
        </form>
        <form action="/phone_setup" method="post">
          <input type="hidden" name="authenticity_token" value="phone-token">
        </form>
      HTML

      expect(described_class.csrf_token(html, action_includes: '/phone_setup')).
        to eq('phone-token')
    end

    it 'raises when no token is present' do
      expect { described_class.csrf_token('<form action="/"></form>') }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /no authenticity_token/)
    end
  end

  describe '.prefilled_otp' do
    it 'reads the code the IdP prefills in development' do
      html = '<input type="text" name="code" id="code" value="123456">'

      expect(described_class.prefilled_otp(html)).to eq('123456')
    end

    it 'falls back to matching on the field name' do
      html = '<input type="text" name="code" value="654321">'

      expect(described_class.prefilled_otp(html)).to eq('654321')
    end

    it 'returns nil when the field is empty, meaning prefill is disabled' do
      html = '<input type="text" name="code" id="code" value="">'

      expect(described_class.prefilled_otp(html)).to be_nil
    end
  end

  describe '.confirm_now_href' do
    it 'finds the load-testing confirmation link by id' do
      html = '<a id="confirm-now" href="/sign_up/email/confirm?confirmation_token=t1">CONFIRM NOW</a>'

      expect(described_class.confirm_now_href(html)).
        to eq('/sign_up/email/confirm?confirmation_token=t1')
    end

    it 'returns nil when the link is absent, meaning the IdP flag is off' do
      expect(described_class.confirm_now_href('<p>check your email</p>')).to be_nil
    end
  end

  describe '.click_immediate_href' do
    it 'extracts the client_side_js handoff target' do
      html = <<~HTML
        <a href="http://localhost:9292/auth/result?code=abc&state=xyz" data-click-immediate>
          Submit
        </a>
      HTML

      expect(described_class.click_immediate_href(html)).
        to eq('http://localhost:9292/auth/result?code=abc&state=xyz')
    end

    it 'returns nil for a server_side handoff, which is a plain redirect' do
      expect(described_class.click_immediate_href('<html></html>')).to be_nil
    end
  end

  describe '.forms and .find_form' do
    let(:html) do
      <<~HTML
        <form action="/second_mfa_reminder" method="post">
          <input type="hidden" name="authenticity_token" value="t">
          <input type="hidden" name="add_method" value="true">
        </form>
        <form action="/second_mfa_reminder" method="post">
          <input type="hidden" name="authenticity_token" value="t">
        </form>
        <form action="/authentication_methods_setup" method="post">
          <input type="hidden" name="_method" value="patch">
          <input type="hidden" name="authenticity_token" value="t2">
        </form>
      HTML
    end

    it 'captures hidden inputs so a form can be replayed' do
      form = described_class.find_form(html, path: '/authentication_methods_setup')

      expect(form.params).to include('authenticity_token' => 't2')
    end

    it "uses Rails' _method override as the effective method" do
      form = described_class.find_form(html, path: '/authentication_methods_setup')

      expect(form.method).to eq('patch')
    end

    it 'can skip the opt-in variant of a dual-button screen' do
      form = described_class.find_form(
        html,
        path: '/second_mfa_reminder',
        without_params: ['add_method'],
      )

      expect(form.params).not_to have_key('add_method')
    end

    it 'returns nil when no form matches' do
      expect(described_class.find_form(html, path: '/nonexistent')).to be_nil
    end
  end

  describe '.form_for_field' do
    it 'locates a form by a field it owns' do
      # The OTP view uses simple_form_for('') and has no useful action, so the
      # harness finds it via the code field instead.
      html = <<~HTML
        <form method="post">
          <input type="hidden" name="authenticity_token" value="otp-token">
          <input type="text" name="code" id="code" value="123456">
        </form>
      HTML

      form = described_class.form_for_field(html, 'code')

      expect(form.params).to eq('authenticity_token' => 'otp-token')
    end

    it 'returns nil when the field is not inside a form' do
      expect(described_class.form_for_field('<input name="code">', 'code')).to be_nil
    end
  end

  describe '.field?' do
    it 'detects a named input' do
      expect(described_class.field?('<input name="user[email]">', 'user[email]')).to be(true)
    end

    it 'is false for an absent input' do
      expect(described_class.field?('<p>hi</p>', 'user[email]')).to be(false)
    end
  end

  describe '.mock_recaptcha_fields' do
    it 'mirrors the fields the mock validator renders' do
      html = '<input type="hidden" name="user[recaptcha_token]" value="mock_token">'

      expect(described_class.mock_recaptcha_fields(html, scope: 'user')).to eq(
        'user[recaptcha_token]' => 'mock_token',
        'user[recaptcha_mock_score]' => '1.0',
      )
    end

    it 'sends nothing when the form has no recaptcha field' do
      expect(described_class.mock_recaptcha_fields('<form></form>', scope: 'user')).to eq({})
    end
  end

  describe '.rp_userinfo?' do
    it 'recognizes the relying party success page' do
      expect(described_class.rp_userinfo?('<span>Received user info:</span>')).to be(true)
    end

    it 'is false otherwise' do
      expect(described_class.rp_userinfo?('<p>Authentication error</p>')).to be(false)
    end
  end

  describe '.error_text' do
    it 'extracts IdP error copy for diagnostics' do
      html = '<div class="usa-alert--error"><p>The password you entered is incorrect.</p></div>'

      expect(described_class.error_text(html)).to eq('The password you entered is incorrect.')
    end
  end
end
