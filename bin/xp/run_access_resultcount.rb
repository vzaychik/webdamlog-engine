require_relative '../../lib/access_runner'
require_relative '../../lib/wlbud/wlerror'
require 'csv'

XP_FILE_DIR = ARGV.first if defined?(ARGV)
XPFILE = "XP_NOACCESS"
RULEFILE = "rules.wdm"
WRITEABLEFILE = "writeable.wdm"

# Parameters:
# * XP_FILE_DIR : The path to the directory with the data generator
#
# By convention :
# * there should be a CSV file named XP_NOACCESS with the list of peer name to
#   start.
# * the program file name of each peer must be an underscore separated string.
#   The last field must be the peername.
def run_access_remote!
  if ARGV.include?("access")
    @access_mode = true
    p "starting experiment with access control on"
  end
  if ARGV.include?("optim1")
    @optim1 = true
    @access_mode = true
    p "optimization 1 is on"
    #load writeable
    writeable = {}
    File.readlines("#{XP_FILE_DIR}/#{WRITEABLEFILE}").each do |fact|
      #parse out the peer and hash by that
      fact[/.*@([a-zA-Z0-9]+)\(/]
      name = $1
      writeable[name] = [] if writeable[name].nil? 
      writeable[name] << fact
    end
  end
  if ARGV.include?("optim2")
    @optim2 = true
    @access_mode = true
    p "optimization 2 - formulas - is on"
  end

  xpfiles = []
  expected_tuples = 0
  #first row is the list of peers
  CSV.foreach(get_run_xp_file) do |row|
    if (xpfiles == [])
      xpfiles = row
      p "Start experiments with #{xpfiles}"
    else
      expected_tuples = row.first.to_i
    end
  end

  if expected_tuples < 1
    p "This scenario will not generate any results, so not running"
    exit 1
  end

  runners = []
  xpfiles.each do |f|
    runners << create_wl_runner(File.join(XP_FILE_DIR,f))
    p "#{runners.last.peername} created"
  end

  num_running = 0

  runners.each do |runner|
    runner.on_shutdown do
      p "Final tick step of #{runner.peername} : #{runner.budtime}"
      num_running -= 1
    end
    if !runner.peername.start_with?("master") && !runner.peername.start_with?("sue")
      donerel = "master_done_" + (@access_mode ? "plusR_" : "") + "at_#{runner.peername}"
      runner.register_callback(donerel.to_sym) do
        p "master is done, shutting #{runner.peername} down"
        runner.stop
      end
    end
  end

  runners.each do |runner|
    if @optim1
      writeable[runner.peername].each { |fct|
        runner.add_facts fct
      }
    end
    runner.run_engine_periodic
    #runner.run_engine
    num_running += 1
    p "#{runner.peername} started"
    if runner.peername == "master0"
      @masterp = runner
      @scenario = "network"
    elsif runner.peername.start_with?("sue")
      @masterp = runner
      @scenario = "album"
    end
  end

  if @masterp != nil
    #inject rules now
    rules = []
    donerules = []
    File.readlines("#{XP_FILE_DIR}/#{RULEFILE}").each do |rule|
      if rule.start_with?("//") == false
        if rule.include?("master_done")
          donerules << rule
        else
          rules << rule
        end
      end
    end
    p "at tick #{@masterp.budtime} injecting rules: #{rules}"
    @masterp.update_add_rules rules

    if @scenario == "network"
      resultrel = "t_i"
    elsif @scenario == "album"
      resultrel = "album_i"
    end
    if @access_mode == true
      resultrel += "_plusR_at_#{@masterp.peername}"
    else
      resultrel += "_at_#{@masterp.peername}"
    end

    first_time_done = true
    @masterp.register_callback(resultrel.to_sym) do
      if @masterp.tables[resultrel.to_sym].length == expected_tuples && first_time_done
        first_time_done = false
        p "master received all tuples, shutting down"
        results = @masterp.tables[resultrel.to_sym].map{ |t| Hash[t.each_pair.to_a] }
        puts "final contents of master's facts: #{results}"
        donerules.each do |rule|
          @masterp.add_rule rule
        end
        @masterp.add_facts ({"done_at_#{@masterp.peername}" => [["1"]]})
        @masterp.dies_at_tick = @masterp.budtime #this should kill on next tick
        @masterp.schedule_extra_tick
      end
    end
  end

  while num_running > 0
    p "still running: #{num_running}"
    sleep 30
  end

end

# Giving a program file generated from data_generators start the peer given in
# the name of the file using the address found in the program file
def create_wl_runner pg_file
  ip_addr = port = ''
  pg_splitted = pg_file.split "_"
  peername = pg_splitted.last
  file = File.new pg_file, "r"
  loop = true
  while loop and line = file.gets
    if(/^peer/.match line and line.include? peername) # find line which contains peer current peer address
      pname = line.split("=").first.strip
      if (/#{peername}$/.match pname)
        peerline = line.split("=").last.strip
        peerline.slice!(-1) # remove last ;
        ip_addr, port = peerline.split ":"
        loop = false
      end
    end
  end
  file.close
  raise WLError, "impossible to find the peername given in the end of the program \
filename: #{peername} in the list of peer specified in the program" if ip_addr.nil? or port.nil?
  puts "creating peer #{peername} on #{ip_addr}:#{port}"
  return WLARunner.create(peername, pg_file, port, {:ip => ip_addr, :measure => true, :accessc => @access_mode, :optim1 => @optim1, :optim2 => @optim2, :noprovenance => true, :debug => false, :tcp => true, :reliable => true })
end # def start_peer

def get_run_xp_file
  raise "WLXP alone is not an experiment, choose one of the xp" unless defined? XPFILE
  return File.join(XP_FILE_DIR, XPFILE)
end

run_access_remote!
