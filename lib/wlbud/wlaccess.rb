require 'bud/lattice-lib'
require 'singleton'

class PList < Bud::SetLattice

  alias_method :base_intersect, :intersect
  alias_method :base_merge, :merge

  def include?(element)
    @v.member? element
  end

  def to_a
    self.reveal.to_a
  end

  def merge(other)
    if (other.kind_of? Omega)
      return other
    else
      base_merge(other)
    end
  end

  def intersect(other)
    if (other.kind_of? Omega)
      return self
    else
      base_intersect(other)
    end
  end
end

class Omega < PList
  include Singleton

  def intersect(other)
    return other
  end

  def merge(other)
    return self
  end

  def include?(element)
    return true
  end

  def contains?(element)
    Bug::BoolLattice.new(true)
  end

  def inspect
    return "<: #{self.to_a}>"
  end

  def to_s
    return "All peers"
  end

  def to_a
    return ["All peers"]
  end

end

class FormulaList < Bud::Lattice
  wrapper_name :formset

  #cannot directly look up include

  def initialize(i="")
    reject_input(i) unless i.kind_of? String
    @v = i
  end

  def to_a
    self.reveal
  end

  def merge(other)
    #simple way is to concatenate with a '+'
    #TODO - do something smarter such as sorting
    if (other.kind_of? Omega)
      other
    else
      wrap_unsafe(@v + "+" + i.reveal)
    end
  end

  def intersect(other)
    #TODO - do something smarter such as sorting
    if (other.kind_of? Omega)
      self
    else
      wrap_unsafe(@v + "*" + i.reveal)
    end
  end
end
