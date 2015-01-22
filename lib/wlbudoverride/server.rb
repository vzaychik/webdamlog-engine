class Bud::BudServer < EM::Connection

  #because of long-message handling, we need to override bud's receive_data method
  #otherwise there are extra ticks computed
  def receive_data(data)
    #standard bud processing from original method
    @pac.feed_each(data) do |obj|
      recv_message(obj)
    end

    # apply the channel filter to each channel's pending tuples
    buf_leftover = {}
    @filter_buf.each do |tbl_name, buf|
      if @channel_filter
        accepted, saved = @channel_filter.call(tbl_name, buf)
      else
        accepted = buf
        saved = []
      end

      unless accepted.empty?
        @bud.inbound[tbl_name] ||= []
        @bud.inbound[tbl_name].concat(accepted)
      end
      buf_leftover[tbl_name] = saved unless saved.empty?
    end
    @filter_buf = buf_leftover
    #end of standard bud processing

    if !@bud.inbound[:chan].nil?
      begin
        #@bud.tick_internal if @bud.running_async
        #puts "there is a message, we'll see when it's picked up"
      rescue Exception => e
        # If we raise an exception here, EM dies, which causes problems (e.g.,
        # other Bud instances in the same process will crash). Ignoring the
        # error isn't best though -- we should do better (#74).
        puts "Exception handling network messages: #{e.class}:#{e}"
        puts e.backtrace
        puts "Inbound messages:"
        @bud.inbound.each do |chn_name, t|
          puts "    #{t.inspect} (channel: #{chn_name})"
        end
        @bud.inbound.clear
      end
    else
      puts "Received an incomplete message, skipping tick until we receive all" if @bud.options[:debug]
    end

    @bud.rtracer.sleep if @bud.options[:rtrace]    
  end
end
