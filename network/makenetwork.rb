def make_network!
  filename = ARGV.first
  alledges = []

  File.readlines(filename).each do |line|
    #break into a tuple
    tuple = line.split(' ')[0..1].map{ |i| i.to_i }
    alledges << tuple
    alledges << tuple.reverse
  end

  #now group by src
  network = alledges.group_by { |i| i.first }
  network.each { |k,v| network[k] = v.map{ |el| el[1]}}

  #now we need to renumber vertices to start with 0
  newids = {}
  network.keys.sort.each_with_index { |oldid,ind| newids[oldid] = ind}

  if ARGV.include? "flat"
    #output number of edges
    puts newids.length
    puts alledges.length
    
    #now out with new ids everywhere
    newids.keys.each { |k|
      network[k].each { |edge|
        puts "#{newids[k]} #{newids[edge]}"
      }
    }
  else
    #now output in sorted order (doesn't have to be sorted, just for sanity)
    network.keys.sort.each do |k|
      puts "#{newids[k]} #{network[k].map{|v| newids[v]}.join(' ')}"
    end
  end
end

make_network!
