class System

  attr_accessor :name
  attr_accessor :attributes # (basebox selection)
  attr_accessor :module_selectors # (filters)
  attr_accessor :module_selections # (after resolution)
  attr_accessor :num_actioned_module_conflicts

  # Initalizes System object
  # @param [Object] name of the system
  # @param [Object] attributes such as base box selection
  # @param [Object] module_selectors these are modules that define filters for selecting the actual modules to use
  def initialize(name, attributes, module_selectors)
    self.name = name
    self.attributes = attributes
    self.module_selectors = module_selectors
    self.module_selections = []
    self.num_actioned_module_conflicts = 0
  end

  # selects from the available modules, based on the selection filters that have been specified
  # @param [Object] available_modules all available modules (vulnerabilities, services, bases)
  # @param [Object] recursion_count (retry count -- used for resolving conflicts by bruteforce randomisation)
  # @return [Object] the list of selected modules
  def resolve_module_selection(available_modules, recursion_count)

    selected_modules = []
    self.num_actioned_module_conflicts = 0

    # for each module specified in the scenario
    module_selectors.each do |module_filter|
      # select based on selected type, access, cve...

      search_list = available_modules.clone
      # shuffle order of available vulnerabilities
      search_list.shuffle!

      # remove any not the type of module we are adding (vulnerabilty/service)
      search_list.delete_if{|x| "#{x.module_type}_selecter" != module_filter.module_type}

      # filter to those that satisfy the attribute filters
      search_list.delete_if{|module_for_possible_exclusion|
        !module_for_possible_exclusion.matches_attributes_requirement(module_filter.attributes)
      }
      Print.verbose "Filtered to modules matching: #{module_filter.attributes.inspect} ~= (n=#{search_list.size})"

      # remove non-options due to conflicts
      search_list.delete_if{|module_for_possible_exclusion|
        check_conflicts_with_list(module_for_possible_exclusion, selected_modules)
      }

      failed_retry = false

      if search_list.length == 0
        failed_retry = true
        Print.err 'Could not find a matching module. Please check the scenario specification'
      else
        # use from the top of the randomised list
        selected = search_list[0]

        # add any modules that the selected module requires
        dependencies = select_required_modules(selected, available_modules, selected_modules)
        if dependencies == nil
          failed_retry = true
        end
      end

      if failed_retry
        # bruteforce conflict resolution (could be more intelligent)
        if self.num_actioned_module_conflicts > 0
          Print.err "During scenario generation #{num_actioned_module_conflicts} module conflict(s) occured..."
        else
          Print.err 'No conflicts, but failed to resolve scenario -- this is a sign there is something wrong in the config (scenario / modules)'
          Print.err 'Please review the scenario -- something is wrong.'
          exit
        end
        if recursion_count < RETRIES_LIMIT
          Print.err "Failed to resolve scenario. Re-attempting to resolve scenario (##{recursion_count + 1})..."
          sleep 1
          return resolve_module_selection(available_modules, recursion_count + 1)
        else
          Print.err "Tried re-randomising #{RETRIES_LIMIT} times. Still no joy."
          Print.err 'Please review the scenario -- something is wrong.'
          exit
        end
      end

      selected_modules = selected_modules + dependencies + [selected]

      Print.std "Selected module: #{selected.printable_name}"
    end
    selected_modules
  end

  def check_conflicts_with_list(module_for_possible_exclusion, selected_modules)
    found_conflict = false
    selected_modules.each do |prev_selected|
      if module_for_possible_exclusion.conflicts_with(prev_selected) ||
          prev_selected.conflicts_with(module_for_possible_exclusion)
        Print.verbose "Excluding incompatible module: #{module_for_possible_exclusion.module_path} (conflicts with #{prev_selected.module_path})"
        self.num_actioned_module_conflicts += 1
        found_conflict = true
      end
    end
    found_conflict
  end

  # for a single dependency
  # returns a module that satisfies the requirement from a list of modules provided
  # returns nil when the requirement cannot be satisfied
  def resolve_dependency(required, provided_modules)
    provided_modules.each do |possibly_add|
      if possibly_add.matches_attributes_requirement(required)
        return possibly_add
      end
    end
    # couldn't satisfy requirement!
    return nil
  end

  ##### TODO TODO TODO TODO TODO : recursive dependency resolution
  ##### TODO: REUSE THE MAIN CODE, rather than repeating logic below

  # returns a list of modules that satisfies all dependencies for the given module
  # returns an empty list if there are no requirements
  # returns nil if unable to fulfil requirements
  def select_required_modules(required_by, available_modules, selected_modules)
    modules_to_add = []
    required_by.requires.each do |required|
      available_modules_rnd = available_modules.clone.shuffle!
      Print.verbose "Resolving dependency: #{required.inspect}"
      # checking whether dependency is satisfied by previously selected modules
      existing = resolve_dependency(required, selected_modules)
      if existing != nil
        Print.verbose "Dependency satisfied by previously selected module: #{existing.printable_name}"
      else
        # checking whether dependency can be satisfied by any available modules
        available_modules_rnd.delete_if{|module_for_possible_exclusion|
          !module_for_possible_exclusion.matches_attributes_requirement(required)
        }
        # removing any potential conflicts
        available_modules_rnd.delete_if{|module_for_possible_exclusion|
          check_conflicts_with_list(module_for_possible_exclusion, selected_modules)
        }
        Print.verbose "Filtering to modules that can satisfy the dependency, without conflicts (->#{available_modules_rnd.size})"
        if available_modules_rnd.size > 0
          to_add = available_modules_rnd[0]
          Print.std "Adding module #{to_add.printable_name} to satisfy dependency of #{required_by.printable_name}"
          modules_to_add.push to_add
        else
          Print.err "Could not satisfy dependency of #{required_by.printable_name}"
          return nil
        end
      end
    end
    modules_to_add
  end

end