# Bud methods overridden in Webdamlog
module Bud

  # Add a delete methods used by deletion via provenance
  class BudCollection

    # Delete a tuple without propagating invalidation.
    #  This is used to delete via the provenance graph deletion propagation algorithm.
    #  This methods to delete should be called in the first step of a webdamlog stage.
    #  Hence the fixpoint will be run after the deletion.
    #  PENDING Check if it could be usefull to delete in delta.
    #  @return the tuple deleted or nil if nothing has been deleted.
    def delete_without_invalidation tuple
      keycols = get_key_vals(tuple)
      if @storage[keycols] == tuple
        v = @storage.delete keycols
      elsif @delta[keycols] == tuple
        v = @delta.delete keycols
      end
      return v
    end

    # Establish a TCP connection to another peer
    def establish_connection(l)
      toplevel = @bud_instance.toplevel
      toplevel.connections[l] = EventMachine::connect l[0], l[1], ConnectionClient, @bud_instance, l
      #this almost never happens. If a connection is not established, unbind is called
      toplevel.connections.delete(l) if toplevel.connections[l].error?
    end

    def send_tcp_data(the_locspec)
      toplevel = @bud_instance.toplevel
      establish_connection(the_locspec) if toplevel.connections[the_locspec].nil?
      if toplevel.connections_status[the_locspec] == true
        toplevel.connections[the_locspec].send_data @wire_buf.string
      else
        toplevel.connections_buffer[the_locspec] = [] if toplevel.connections_buffer[the_locspec].nil?
        toplevel.connections_buffer[the_locspec].push(@wire_buf.string.clone)
      end
    end
  end


  class ConnectionClient < EM::Connection
    def initialize(bud, locspec)
      @bud = bud.toplevel
      @locspec = locspec
      @connected = false
      @bud.connections_status[@locspec] = false
    end

    def connection_completed
      until @bud.connections_buffer[@locspec].empty?
        str = @bud.connections_buffer[@locspec].shift
        @bud.connections[@locspec].send_data(str)
      end
      @bud.connections_status[@locspec] = true
    end

    def unbind
      @bud.connections_status[@locspec] = false
      @bud.connections.delete(@locspec)
    end

  end

end
