
# ---------------------------------------------------------------------------------------------------------------------
# Units and support element classes:
module GxG
  module Units
    class << self
      @@interpreters = []
    end
    # this module is used for interpreting text into denominations and multipliers., and general support for various units of measure
    def self.unit_interpreters(categories=:any)
      unless categories == :any
        unless categories.is_a?(Array)
          categories = [(categories)]
        end
      end
      unit_list = []
      GxG::Units.constants.to_enum.each do |unit_handler|
        unit_handler = GxG::Units.const_get(unit_handler)
        if (unit_handler.is_any?([Class, Module]) && unit_handler.respond_to?(:interpret) && unit_handler.respond_to?(:categories))
          if categories == :any
            unit_list << unit_handler
          else
            categories.to_enum.each do |category|
              if unit_handler::categories.include?(category)
                unit_list << unit_handler
              end
            end
          end
        end
      end
      #
      unit_list
    end
    #
    def self.refresh_units_registry()
      # SOMEDAY: Thread-safety?
      @@interpreters = self.unit_interpreters()
    end
    #
    def self.interpret_units(params={})
      # {:text => quanta,:categories => categories,:locale => locale}
      quanta_string = (params[:text] || "")
      categories = (params[:categories] || :any)
      locale = (params[:locale] || :en_US)
      numeric_base = (params[:base] || 10)
      unless categories == :any
        unless categories.is_a?(Array)
          categories = [(categories)]
        end
      end
      results = []
      @@interpreters.to_enum.each do |interpreter|
        entry = nil
        if categories == :any
          entry = interpreter::interpret(quanta_string.to_s,locale,numeric_base)
        else
          categories.to_enum.each do |category|
            if interpreter::categories.include?(category)
              entry = interpreter.interpret(quanta_string.to_s,locale,numeric_base)
            end
          end
        end
        if entry
          results << entry
        end
      end
      {:result => results}
    end
    module Bits
      #
    end
    module Bytes
      def self.categories()
        [:numeric, :byte, :memory, :storage, :computer]
      end
      def self.interpret(quanta_string="",interpret_for_locale=:en_US,interpret_for_numeric_base=10)
        multiplier = nil
        #
        case quanta_string.to_s.downcase.to_sym
          # Attribution: http://whatsabyte.com/
          # Attribution: https://en.wikipedia.org/wiki/Exabyte
          # Note: I am electing to count along the 1024 (to the power) rule.  Hard drive manufacturers can kiss my rosey-red,
          # I'll not bugger my enumeration standard for their bloody sales force. :P  Thus:
          # I've attempted to include the IS and IEC terms and abbreviations.
          # LATER: add ability to distinguish case: Kb = kiloBIT, KB = KiloBYTE, etc
        when :byte, :bytes
          multiplier = 1
        when :kb, :kib, :kilobyte, :kilobytes, :kibibyte, :kibibytes
          multiplier = 1024 ** 1
        when :mb, :mib, :megabyte, :megabytes, :mebibyte, :mebibytes
          multiplier = 1024 ** 2
        when :gb, :gib, :gigabyte, :gigabytes, :gibibyte, :gibibytes
          multiplier = 1024 ** 3
        when :tb, :tib, :terabyte, :terabytes, :tebibyte, :tebibytes
          multiplier = 1024 ** 4
        when :pb, :pib, :petabyte, :petabytes, :pebibyte, :pebibytes
          multiplier = 1024 ** 5
        when :eb, :eib, :exobyte, :exobytes, :exbibyte, :exbibytes
          multiplier = 1024 ** 6
        when :zb, :zib, :zettabyte, :zettabytes, :zebibyte, :zebibytes
          multiplier = 1024 ** 7
        when :yb, :yib, :yottabyte, :yottabytes, :yobibyte, :yobibytes
          multiplier = 1024 ** 8
        when :bb, :bib, :brontobyte, :brontobytes
          multiplier = 1024 ** 9
        when :geopbyte, :geopbytes
          # TODO: GeopByte: need to find missing SI and IEC abbreviations
          multiplier = 1024 ** 10
        end
        #
        if multiplier
          {:quantum => {:byte => multiplier}, :attributes => nil}
        else
          nil
        end
      end
    end
  end
end
# Initial setup:
::GxG::Units::refresh_units_registry()
#