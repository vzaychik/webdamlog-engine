class Hash
  # take keys of hash and transform those to a symbols
  #  def self.transform_keys_to_symbols(value)
  #    return value if not value.is_a?(Hash)
  #    hash = value.inject({}){|memo,(k,v)| memo[k.to_sym] = Hash.transform_keys_to_symbols(v); memo}
  #    return hash
  #  end

  # Take keys of hash and transform those to a symbols.
  def self.transform_keys_to_symbols(value, depth=0)
    if not value.is_a?(Hash) or depth == 0
      return value
    end
    hash = value.inject({}) do |memo,(k,v)|
      memo[k.to_sym] = Hash.transform_keys_to_symbols(v, depth-1);
      memo
    end
    return hash
  end
  
end