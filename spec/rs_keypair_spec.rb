require 'spec_helper'
require 'tmpdir'

RSpec.describe LoginGov::OidcSinatra::RsKeypair do
  around do |example|
    Dir.mktmpdir { |dir| @dir = dir; example.run }
  end

  let(:key_path) { File.join(@dir, 'rs_demo.key') }
  let(:crt_path) { File.join(@dir, 'rs_demo.crt') }

  it 'generates a self-signed RSA 2048 pair for records-api.agency.localdev, valid ten years' do
    expect(described_class.ensure!(key_path:, crt_path:)).to be true

    key = OpenSSL::PKey::RSA.new(File.read(key_path))
    cert = OpenSSL::X509::Certificate.new(File.read(crt_path))
    expect(key.n.num_bits).to eq 2048
    expect(cert.subject.to_s).to eq '/CN=records-api.agency.localdev'
    expect(cert.issuer).to eq cert.subject
    expect(cert.public_key.to_pem).to eq key.public_key.to_pem
    expect(cert.verify(key)).to be true
    expect(cert.not_after - cert.not_before).to be_within(1).of(10 * 365 * 24 * 60 * 60)
    expect(File.stat(key_path).mode & 0o777).to eq 0o600
  end

  it 'leaves an existing pair alone' do
    described_class.ensure!(key_path:, crt_path:)
    before = File.read(key_path)

    expect(described_class.ensure!(key_path:, crt_path:)).to be false
    expect(File.read(key_path)).to eq before
  end
end
