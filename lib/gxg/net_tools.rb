
#
# ### Networking Section of GxG
module GxG
  #
  module Networking
    def self.wget(the_url=nil, options={})
      result = false
      begin
        unless options.is_a?(::Hash)
          options = {}
        end
        if the_url.is_a?(::String)
          the_url = ::URI::parse(the_url)
        end
        if the_url.is_a?(::URI::Generic)
          if the_url.scheme.to_s.downcase.include?("https") || options[:use_ssl] == true
            client = ::GxG::Networking::HttpsClient.new(the_url, options)
          else
            client = ::GxG::Networking::HttpClient.new(the_url, options)
          end
          response = client.get(the_url, options.merge({:raw_response => true}))
          if response
            if response.is_a?(::File)
              result = response
            else
              if options[:raw_response]
                result = response
              else
                result = response.body
              end
            end
          else
            raise Exception, "Failed to get a response."
          end
        else
          raise ArgumentError, "You MUST specify a valid URI"
        end
      rescue Exception => the_error
        log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
      end
      result
    end
  end
  #
end