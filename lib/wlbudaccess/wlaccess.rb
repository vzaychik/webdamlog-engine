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

  def to_s
    self.reveal.to_a.to_s
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

  def empty?
    return @v.empty?
  end
end

class Omega < PList
  include Singleton

  wrapper_name :omega

  def intersect(other)
    if other.kind_of?(PList) || other.kind_of?(FormulaList)
      return other
    elsif other.kind_of?(String)
      return FormulaList.new(other)
    else
      reject_input(other)
    end
  end

  def merge(other)
    return self
  end

  def include?(element)
    return true
  end

  def empty?
    false
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

  #using postfix notation for simplicity

  def initialize(i="")
    reject_input(i) unless i.kind_of? String
    @v = i
  end

  def to_a
    return @v
  end

  def to_s
    return @v
  end

  def merge(other)
    #simple way is to concatenate with a '+'
    #TODO - do something smarter such as sorting
    if (other.kind_of? Omega)
      other
    else
      if other.kind_of? FormulaList
        otherv = other.to_s
      elsif other.kind_of? String
        otherv = other
      else
        reject_input(other)
      end

      #FIXME - this check for include might lead to incorrect results in complex expressions
      if @v.include? otherv
        self
      elsif otherv.include? @v
        wrap_unsafe(otherv)
      else
        wrap_unsafe(@v + " " + otherv + " +")
      end
    end
  end

  def intersect(other)
    #TODO - do something smarter such as sorting and eliminating duplicates
    if (other.kind_of? Omega)
      self
    else
      if other.kind_of? FormulaList
        otherv = other.to_s
      elsif other.kind_of? String
        otherv = other
      else
        reject_input(other)
      end

      #FIXME - this check for include might lead to incorrect results in complex expressions
      if @v.include? otherv
        self
      elsif otherv.include? @v
        wrap_unsafe(otherv)
      else
        wrap_unsafe(@v + " " + otherv + " *")
      end
    end
  end
end
