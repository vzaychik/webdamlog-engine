require_relative '../../lib/webdamlog_runner'
require_relative '../../lib/wlbud/wlerror'
require 'csv'

XP_FILE_DIR = ARGV.first if defined?(ARGV)
SLEEP_TIME = ARGV[1].to_f if (ARGV[1] != nil)
XPFILE = "XP_NOACCESS"
RULEFILE = "rules.wdm"

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
  else
    @access_mode = false
    p "starting experiment with access control off"
  end
  if ARGV.include?("optim1")
    @optim1 = true
    p "optimization 1 is on"
  end

  xpfiles = []
  numpeers = 0
  #first row is the list of peers
  CSV.foreach(get_run_xp_file) do |row|
    if (xpfiles == [])
      xpfiles = row
      p "Start experiments with #{xpfiles}"
    else
      numpeers = row.first.to_i
    end
  end

  runners = []
  xpfiles.each do |f|
    runners << create_wl_runner(File.join(XP_FILE_DIR,f))
    p "#{runners.last.peername} created"
  end

  runners.each do |runner|
    runner.on_shutdown do
      p "Final tick step of #{runner.peername} : #{runner.budtime}"
    end
  end

  runners.each do |runner|
    runner.run_engine
    p "#{runner.peername} started"
    if runner.peername == "master0"
      @masterp = runner
    end
  end

  #see if all the other peers have come up before sending rules out
  total_attempts = 0
  if @masterp != nil
    if @access_mode == true
      relname = "peers_up_i_ext_at_master0"
    else
      relname = "peers_up_i_at_master0"
    end
    until @masterp.snapshot_facts(relname.to_sym).length == numpeers
      if total_attempts > (numpeers + 10)
        p "experiment run failed down to timeout on getting all peers up"
        exit 1
      else
        p "at tick #{@masterp.budtime} not all peers are up yet, sleeping"
        sleep 1
        total_attempts += 1
      end
    end

    #inject rules now
    rules = []
    File.readlines("#{XP_FILE_DIR}/#{RULEFILE}").each do |rule|
      if rule.start_with?("//") == false
        rules << rule
      end
    end
    p "at tick #{@masterp.budtime} injecting rules: #{rules}"
    @masterp.update_add_rules rules
  end

  @sleep_time = SLEEP_TIME
  p "running for #{@sleep_time} seconds"
  sleep @sleep_time

  p "stopping runners now that #{@sleep_time} seconds expired"

  if @masterp != nil
    if @access_mode == true
      puts "final contents of master's facts: #{@masterp.snapshot_facts(:t_i_ext_at_master0)}"
    else
      puts "final contents of master's facts: #{@masterp.snapshot_facts(:t_i_at_master0)}"
    end
  end

  runners.each do |runner|
    runner.stop
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
      peerline = line.split("=").last.strip
      peerline.slice!(-1) # remove last ;
      ip_addr, port = peerline.split ":"
      loop = false
    end
  end
  file.close
  raise WLError, "impossible to find the peername given in the end of the program \
filename: #{peername} in the list of peer specified in the program" if ip_addr.nil? or port.nil?
  puts "creating peer #{peername} on #{ip_addr}:#{port}"
  return WLRunner.create(peername, pg_file, port, {:ip => ip_addr, :measure => true, :accessc => @access_mode, :optim1 => @optim1, :noprovenance => true, :debug => false})
end # def start_peer

def get_run_xp_file
  raise "WLXP alone is not an experiment, choose one of the xp" unless defined? XPFILE
  return File.join(XP_FILE_DIR, XPFILE)
end

run_access_remote!
