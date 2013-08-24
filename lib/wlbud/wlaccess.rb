class Omega < Set
  def &(other)
    return other
  end

  def include?(element)
    return true
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

class Set
  alias_method :base_intersect, :&

  def &(other)
    if (other.kind_of? Omega)
      return other & self
    else
      base_intersect(other)
    end
  end
end
