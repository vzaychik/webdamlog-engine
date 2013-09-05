require 'bud/lattice-lib'

class PList < Bud::SetLattice
  alias_method :base_intersect, :intersect

  def merge(i)
    wrap_unsafe(i.reveal)
  end
  
  def include?(element)
    @v.member? element
  end

  def to_a
    self.reveal.to_a
  end

  def intersect(other)
    if (other.kind_of? Omega)
      return other.intersect(self)
    else
      base_intersect(other)
    end
  end
end

class Omega < PList

  def intersect(other)
    return other
  end

  def include?(element)
    return true
  end

  def contains?(element)
    Bug::BoolLattice.new(true)
  end

  def inspect
    return "All peers"
  end

  def to_s
    return "All peers"
  end

  def to_a
    return [Omega]
  end

end

