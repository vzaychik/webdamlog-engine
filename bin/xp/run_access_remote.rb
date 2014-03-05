require_relative '../../lib/webdamlog_runner'
require_relative '../../lib/wlbud/wlerror'
require 'csv'

# XP_FILE_DIR = "/home/ec2-user/out1384232017478"
XP_FILE_DIR = ARGV.first if defined?(ARGV)
NUM_ITER = ARGV[1].to_i if (ARGV[1] != nil)
SLEEP_TIME = 0.2
SLEEP_TIME = ARGV[2].to_f if (ARGV[2] != nil)
XPFILE = "XP_NOACCESS"

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
  ticks = 0
  #first row is the list of peers
  #the second row is the number of ticks for this test
  CSV
  CSV.foreach(get_run_xp_file) do |row|
    if (xpfiles == [])
      xpfiles = row
      p "Start experiments with #{xpfiles}"
    else
      ticks = row.first.to_i
    end
  end

  #add a buffer of 10 ticks
  ticks += 10
  p "Running for #{ticks} ticks"

  runners = []
  xpfiles.each do |f|
    runners << create_wl_runner(File.join(XP_FILE_DIR,f))
    p "#{runners.last.peername} created"
  end
  ticks.times do
    runners.reverse_each do |runner|
      runner.tick
      sleep SLEEP_TIME
    end
  end
  
  runners.reverse_each do |runner|
    runner.sync_do do
      runner.measure_obj.dump_measures
      p "Final tick step of #{runner.peername} : #{runner.budtime}"
    end
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
  return WLRunner.create(peername, pg_file, port, {:ip => ip_addr, :measure => true, :accessc => @access_mode, :optim1 => @optim1})
end # def start_peer

def get_run_xp_file
  raise "WLXP alone is not an experiment, choose one of the xp" unless defined? XPFILE
  return File.join(XP_FILE_DIR, XPFILE)
end

run_access_remote!
