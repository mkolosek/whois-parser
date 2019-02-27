#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.nic.at.rb'

module Whois
  class Parsers

    # Parser for the whois.nic.at server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicAt < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisNicAt

      property_supported :domain do
        node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        node("% nothing found")
      end

      property_supported :available? do
        !invalid? && node("Status") == "free"
      end

      property_supported :registered? do
        !invalid? && !available?
      end

      property_not_supported :created_on

      property_supported :updated_on do
        node("Changed") { |value| parse_time(value) }
      end

      property_not_supported :expires_on

      property_supported :registrar do
        node("registrar")
      end

      property_supported :registrant_contacts do
        build_contact("Holder", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin-C", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech-C", Parser::Contact::TYPE_TECHNICAL)
      end


      # Nameservers are listed in the following formats:
      #
      #   Nserver:     ns1.prodns.de. 213.160.64.75
      #   Nserver:     ns1.prodns.de.
      #
      property_supported :nameservers do
        node("nserver") do |values|
          values.map do |line|
            name, ipv4 = line.split(/\s+/)
            Parser::Nameserver.new(name: name, ipv4: ipv4)
          end
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   % Error: 55000000002 Connection refused; access control limit reached.
      #
      def response_throttled?
        !!node("response:throttled")
      end

      def response_error?
        !!node("response:error")
      end

      def version
        cached_properties_fetch :version do
          if content_for_scanner =~ /^% Version: (.+)$/
            $1
          end
        end
      end

      # NEWPROPERTY invalid?
      def invalid?
        cached_properties_fetch :invalid? do
          node("Status") == "invalid" ||
          response_error?
        end
      end

      private

      def build_contact(element, type)
        node(element) do |raw|
          Parser::Contact.new(raw) do |c|
            c.type = type
          end
        end
      end

    end

  end
end
