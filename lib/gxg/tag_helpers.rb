#
require 'securerandom'
module Padrino
  module Helpers
    module TagHelpers
      # See: https://github.com/padrino/padrino-framework/blob/master/padrino-helpers/lib/padrino-helpers/tag_helpers.rb
      def accordian_tag(the_id=nil, sections=nil)
        # id => <uuid>, :sections => [{:heading => "", :content => ""}]
        if the_id.is_a?(::Array)
          sections = the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output = SafeBuffer.new
        output.safe_concat "<div id='#{the_id.to_s}'>"
        sections.each do |the_section|
          output.safe_concat "<h3>#{the_section[:heading].to_s}</h3>"
          output.safe_concat "<div>"
          output.safe_concat the_section[:content].to_s
          output.safe_concat "</div>"
        end
        output.safe_concat "</div><script>$('##{the_id.to_s}').accordion();</script>"
        output
      end
      #
      def autocomplete_tag(the_id=nil, the_terms=nil)
        if the_id.is_a?(::Array)
          the_terms = the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output = SafeBuffer.new
        output.safe_concat( input_tag(:text, :name => the_id.to_s, :id => the_id.to_s) )
        # output.safe_concat "<input type='text' id='#{the_id.to_s}'>"
        output.safe_concat "<script>var terms#{the_id.to_s.gsub("-","")} = ["
        the_terms.each do |the_term|
          output.safe_concat ("'#{the_term.to_s}'")
          unless the_term == the_terms.last
            output.safe_concat(",")
          end
        end
        output.safe_concat "];"
        output.safe_concat "$( '##{the_id.to_s}' ).autocomplete({source: terms#{the_id.to_s.gsub("-","")}});</script>"
      end
      #
      def gxg_button_tag(the_id=nil, options={})
        # Options: :title => <string>,
        # :javascript => <string>,
        # :image => {:position => :full,:top,:left,:right,:bottom, :source => <path> :height => <int>, :width => <int>}
        if the_id.is_a?(::Hash)
          options = the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output = SafeBuffer.new
        if options[:image].is_a?(::Hash)
          output.safe_concat("<div id='#{the_id.to_s}'>")
          img_opts = {}
          if options[:image][:height]
            img_opts[:height] = options[:image][:height]
          end
          if options[:image][:width]
            img_opts[:width] = options[:image][:width]
          end
          if options[:image][:position] == :full
            output.safe_concat("<table><tr><td>" + image_tag(options[:image][:source], img_opts) + "</td></tr></table>")
          else
            # top, left, right, bottom of title text?
            case options[:image][:position]
            when :top
              output.safe_concat("<table><tr><td>" + image_tag(options[:image][:source], img_opts) + "</td></tr><tr><td>#{options[:title]}</td></tr></table>")
            when :bottom
              output.safe_concat("<table><tr><td>#{options[:title]}</td></tr><tr><td>" + image_tag(options[:image][:source], img_opts) + "</td></tr></table>")
            when :left
              output.safe_concat("<table><tr><td>" + image_tag(options[:image][:source], img_opts) + "</td><td>#{options[:title]}</td></tr></table>")
            when :right
              output.safe_concat("<table><tr><td>#{options[:title]}</td><td>" + image_tag(options[:image][:source], img_opts) + "</td></tr></table>")
            end
          end
          output.safe_concat("</div>")
        else
          output.safe_concat("<div id='#{the_id.to_s}'>#{options[:title].to_s}</div>")
        end
        output.safe_concat("<script>$('##{the_id.to_s}').button();</script>")
        if options[:javascript].is_a?(::String)
          output.safe_concat("<script>#{options[:javascript].to_s}</script>")
        end
        output
      end
      #
      def radio_tag(the_id=nil,title=nil)
        output = SafeBuffer.new
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output.safe_concat("<label for='#{the_id}'>#{title}</label>")
        output.safe_concat("<input type='radio' name='#{the_id}' id='#{the_id}'>")
        output
      end
      #
      def radio_group(legend=nil,button_names=nil)
        # Waiting on Fix: https://bugs.jqueryui.com/ticket/15308#comment:1
        output = SafeBuffer.new
        output.safe_concat("<fieldset><legend>#{legend.to_s}</legend>")
        button_names.each do |the_name|
          output.safe_concat(radio_tag(nil,the_name))
        end
        output.safe_concat("</fieldset>")
        output.safe_concat("<script>$('input[type=radio]').checkboxradio();</script>")
        output
      end
      #
      def control_group(content="", options={:vertical => false}, &block)
        #
        output = SafeBuffer.new
        if options[:vertical]
          output.safe_concat("<div class='controlgroup-verticle'>")
        else
          output.safe_concat("<div class='controlgroup'>")
        end
        if block.respond_to?(:call)
          output.safe_concat(block.call())
        else
          output.safe_concat(content)
        end
        output.safe_concat("</div>")
        if options[:vertical]
          output.safe_concat("<script>$('.controlgroup-verticle').controlgroup({'direction': 'vertical'});</script>")
        else
          output.safe_concat("<script>$('.controlgroup').controlgroup();</script>")
        end
        output
      end
      #
      def datepicker_tag(the_id=nil,title="")
        output = SafeBuffer.new
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output.safe_concat("#{title.to_s}<input type='text' id='#{the_id.to_s}'>")
        output.safe_concat("<script>$('##{the_id.to_s}').datepicker();</script>")
        output
      end
      #
      def dialog_tag(the_id=nil, title="", content="", &block)
        output = SafeBuffer.new
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output.safe_concat("<div title='#{title.to_s}' id='#{the_id.to_s}'>")
        if block.respond_to?(:call)
          output.safe_concat(block.call())
        else
          output.safe_concat(content)
        end
        output.safe_concat("</div>")
        output.safe_concat("<script>$('##{the_id.to_s}').dialog();</script>")
        output
      end
      #
      def slider_tag(the_id=nil, options={})
        output = SafeBuffer.new
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output.safe_concat("<div id='#{the_id.to_s}'>")
        if options[:content].is_a?(::String)
          output.safe_concat(options[:content].to_s)
        end
        output.safe_concat("</div>")
        if options[:javascript].is_a?(::String)
          output.safe_concat("<script>$('##{the_id.to_s}').slider(#{options[:javascript].to_s});</script>")
        else
          output.safe_concat("<script>$('##{the_id.to_s}').slider();</script>")
        end
        output
      end
      #
      def spinner_tab(the_id=nil, options={})
        output = SafeBuffer.new
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output.safe_concat("<input id='#{the_id.to_s}'")
        if options[:name].is_a?(::String)
          output.safe_concat(" name='#{options[:name].to_s}'")
        end
        if options[:value]
          output.safe_concat(" name='#{options[:value].to_s}'")
        end
        output.safe_concat(">")
        if options[:javascript].is_a?(::String)
          output.safe_concat("<script>$('##{the_id.to_s}').spinner(#{options[:javascript].to_s});</script>")
        else
          output.safe_concat("<script>$('##{the_id.to_s}').spinner();</script>")
        end
        output
      end
      #
      def tabs_tag(the_id=nil, sections=nil, options={})
        # id => <uuid>, :sections => [{:heading => "", :content => ""}]
        if the_id.is_a?(::Array)
          sections = the_id
          options = sections
          the_id = ::SecureRandom::uuid.to_s
        end
        unless the_id
          the_id = ::SecureRandom::uuid.to_s
        end
        output = SafeBuffer.new
        section_details = {}
        output.safe_concat "<div id='#{the_id.to_s}'>"
        sections.each do |the_section|
          section_id = ::SecureRandom::uuid.to_sym
          section_details[(section_id)] = {:heading => the_section[:heading], :content => the_section[:content]}
        end
        output.safe_concat "<ul>"
        section_details.each_key do |the_uuid|
          output.safe_concat "<li><a href='##{the_uuid.to_s}'>#{section_details[(the_uuid)][:heading].to_s}</a></li>"
        end
        output.safe_concat "</ul>"
        section_details.each_key do |the_uuid|
          output.safe_concat "<div id='#{the_uuid.to_s}'>#{section_details[(the_uuid)][:content].to_s}</div>"
        end
        output.safe_concat "</div>"
        if options[:javascript].is_a?(::String)
          output.safe_concat("<script>$('##{the_id.to_s}').tabs(#{options[:javascript].to_s});</script>")
        else
          output.safe_concat("<script>$('##{the_id.to_s}').tabs();</script>")
        end
        output
      end
      #
      def currency_string(amount=0.0)
        result = ""
        if amount.to_s.split(".")[1].size < 2
          result = ("$" << amount.to_s << "0")
        else
          result = ("$" << amount.to_s)
        end
        result
      end
      #
    end
  end
end