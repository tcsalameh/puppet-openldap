require 'tempfile'
require 'base64'
require 'uri'
require 'puppet/network/http/compression'

if Puppet::PUPPETVERSION.split('.').first.to_i < 4
  require 'puppet/network/http/api/v1'
else
  require 'puppet/network/http/api/indirected_routes'
end

Puppet::Type.type(:openldap_org).provide(:org,
                                         :parent => Puppet::Type.type(:openldap).provider(:olc)) do
  def self.instances
    config_objects = self.parse_slapcat('cn=config')
    olc_database_configs = config_objects.select do |resource|
      resource.attributes.has_key?("olcDatabase") && resource.attributes.has_key?("olcSuffix")
    end
    olc_database_configs.reduce([]) do |memo, resource|
      memo + self.parse_slapcat(resource.attributes["olcSuffix"][0])
    end
  end
end
