module SecureJwt::Configs

  def config
    @config ||= Configurator.new
  end

  class Configurator
    attr_accessor :master_key

    private

    def clear!
      @master_key = nil
    end
  end
end