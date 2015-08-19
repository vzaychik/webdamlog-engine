# Bud methods override for access control
module Bud

  class BudCollection
    # Establish a TCP connection to another peer
    def establish_connection(l)
      toplevel = @bud_instance.toplevel
      toplevel.connections[l] = EventMachine::connect l[0], l[1], ConnectionClient, @bud_instance, l
    end

    def send_tcp_data(the_locspec)
      toplevel = @bud_instance.toplevel
      establish_connection(the_locspec) if toplevel.connections[the_locspec].nil?
      if toplevel.connections_status[the_locspec] == true
        toplevel.connections[the_locspec].send_data @wire_buf.string
      elsif @bud_instance.options[:reliable]
        toplevel.connections_buffer[the_locspec] = [] if toplevel.connections_buffer[the_locspec].nil?
        toplevel.connections_buffer[the_locspec].push(@wire_buf.string.clone)
      end #otherwise silently drop messages that can't be sent
    end
  end # class BudCollection

  class ConnectionClient < EM::Connection
    def initialize(bud, locspec)
      @bud = bud.toplevel
      @locspec = locspec
      @connected = false
      @bud.connections_status[@locspec] = false
    end

    def connection_completed
      until @bud.connections_buffer[@locspec].nil? or @bud.connections_buffer[@locspec].empty?
        str = @bud.connections_buffer[@locspec].shift
        send_data(str)
      end
      @bud.connections_status[@locspec] = true
    end

    def unbind
      @bud.connections_status[@locspec] = false
      @connected = false
      unless @bud.connections_buffer[@locspec].nil? or @bud.connections_buffer[@locspec].empty?
        EventMachine.add_timer(1) { reconnect(@locspec[0], @locspec[1]) }
      else
        @bud.connections[@locspec].delete(@locspec)
      end
    end
  end

end
