# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/tvwhois.verisign-grs.com/tv/property_nameserver_no_nameserver.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/tvwhois.verisign-grs.com.rb'

describe Whois::Parsers::TvwhoisVerisignGrsCom, "property_nameserver_no_nameserver.expected" do

  subject do
    file = fixture("responses", "tvwhois.verisign-grs.com/tv/property_nameserver_no_nameserver.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers).to eq([])
    end
  end
end