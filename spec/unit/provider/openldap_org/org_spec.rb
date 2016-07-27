require 'spec_helper'

describe Puppet::Type.type(:openldap_org).provider(:org) do

  before :each do
    Puppet::Type.type(:openldap_org).stubs(:defaultprovider).returns described_class
  end

  describe '.instances' do
    it 'should have an instances method' do
      expect(described_class).to respond_to(:instances)
    end

    it 'should get existing objects by running slapcat' do
      described_class.expects(:slapcat).with('-b', 'cn=config', '-o', 'ldif-wrap=no', '-H', 'ldap:///???').returns File.read(my_fixture('slapcat_cn=config'))
      described_class.expects(:slapcat).with('-b', 'ou=example', '-o', 'ldif-wrap=no', '-H', 'ldap:///???').returns File.read(my_fixture('slapcat_ou=example'))
      expect(described_class.instances.map(&:name)).to eq([
        'ou=example',
      ])
    end
  end
end
