import re
import sys
import copy
import logging
import io
from text_match import TextMatch


class HierarchicalConfiguration(object):

    """
    A class for representing and comparing Cisco running configurations in a
    hierarchical tree data structure.  An instance represents one line of
    a configuration.  Each instance has text, indentation, and a list of child items.

    Example usage:
        #Setup variables needed by HierarchicalConfiguration
        hier_tags = self.host_variable_space['hier_tags']
        hier_options = dict()
        hier_options['hostname'] = self.hostname
        hier_options.update(self.host_variable_space['hier_options'])

        #Build HierarchicalConfiguration object for the Running Config
        running_config_hier = HierarchicalConfiguration(options=hier_options)
        running_config_hier.from_file(self.options['running_config_file'])
        print running_config_hier.logs.getvalue()

        #Build HierarchicalConfiguration object for the Compiled Config
        compiled_config_hier = HierarchicalConfiguration(options=hier_options)
        compiled_config_hier.from_file(self.options['compiled_config_file'])
        print running_config_hier.logs.getvalue()

        #Build HierarchicalConfiguration object for the Remediation Config
        remediation_config_hier = compiled_config_hier.deep_diff_tree_with(running_config_hier)
        remediation_config_hier.add_sectional_exiting()
        remediation_config_hier.add_tags(hier_tags)
        remediation_config = remediation_config_hier.to_detailed_ouput()
        print remediation_config_hier.logs.getvalue()


    #Example supporting data structures
    hier_options:
      #Enabled/Disables idempotent ACL handling for IOS-XR
      idempotent_acl_iosxr: true

      #if there is a delta, overwrite these parents instead of one of their children
      sectional_overwrite:
      - ^template

      sectional_overwrite_no_negate:
      - ^as-path-set
      - ^prefix-set
      - ^route-policy
      - ^extcommunity-set
      - ^community-set

      parent_allows_duplicate_child:
      - ^route-policy

      sectional_exiting:
      - parent_expression: ^route-policy
        exit_text: end-policy
      - parent_expression: ^policy-map
        exit_text: end-policy-map

      #adds +1 indent to lines following start_expression and removes the +1 indent for lines following end_expression
      indent_adjust:
      - start_expression: ^\s*template
        end_expression: ^\s*end-template

      #substitions against the full multi-line config text
      full_text_sub:
      - search: 'banner exec (\^?\S)\w*\n(.*\n)+\\1\s*\n'
        replace: ''
      - search: 'banner motd (\^?\S)\w*\n(.*\n)+\\1\s*\n'
        replace: ''

      #substitions against each line of the config text
      per_line_sub:
      - search: ^Building configuration.*
        replace: ''
      - search: .*message-digest-key.*
        replace: ''
      - search: .*password.*
        replace: ''

      idempotent_commands_blacklist: []

      #These commands do not require negation, they simply overwrite themselves
      idempotent_commands:
      - ^\s*cost
      - logging \d+.\d+.\d+.\d+ vrf MGMT
      - soft-reconfiguration inbound

      #Default when expression: list of expressions
      negation_default_when: []
      #- expressions

      #Negate substitutions: expression -> negate with
      negation_negate_with: []
      #- match: expression
      #  use: command

    hier_tags:
      safe:
      - section:
        - startswith: snmp
        action: add
      - section:
        - startswith: router bgp
        - startswith: neighbor-group
        - startswith: address-family
        - re_search: route-policy (DENY|DROP)
        action: add
      - section:
        - startswith: interface
        - equals: no carrier-delay up 0 down 0
        action: add
    """

    def __init__(self, parent=None, text=None, indent_level=None, options=None):

        if text == None:
            self.text = text
        else:
            self.text = text.strip()

        self.parent = parent
        if self._is_base_instance():
            self.indent_level = -1
            self.options = options
            # Create the logger
            self.logger = logging.getLogger('hier_logger')
            self.logger.setLevel(logging.DEBUG)
            # Setup the console handler with a StringIO object
            self.logs = io.StringIO()
            ch = logging.StreamHandler(self.logs)
            ch.setLevel(logging.DEBUG)
            # Add the console handler to the logger
            self.logger.addHandler(ch)
        else:
            self.indent_level = indent_level
            self.options = self.parent.options
            self.logger = self.parent.logger
            self.logs = self.parent.logs

        self.children = []
        self.tags = []
        self.comment = ''
        self.new_in_config = False

    def __repr__(self):
        return 'HierarchicalConfiguration({}, {}, {}, {})'.format(
                self.parent,
                self.text,
                self.indent_level,
                self.options)

    def __str__(self):
        return self.text

    def _is_base_instance(self):
        """ Check if this instance is the base instance in the hierarchy """
        if self.parent is None:
            return True
        else:
            return False

    def _delete(self):
        """ Delete the current object from its parent """
        self.parent.children[:] = [c for c in self.parent.children if not id(self) == id(c)]

    def _child_exists(self, text):
        """ Determine if child exists given the text of the child """
        for child in self.children:
            if child.text == text:
                return True
        return False

    def get_child(self, text):
        """ Find a child by its text and return it. If it is not found, return None """
        for child in self.children:
            if child.text == text:
                return child
        return None

    def _del_child(self, text):
        """ Delete all children with the provided text """
        self.children[:] = [c for c in self.children if c.text != text]

    def _duplicate_child_allowed_check(self):
        """ Determine if duplicate(identical text) children are allowed under the parent """
        for expression in self.options['parent_allows_duplicate_child']:
            if not self._is_base_instance() and re.search(expression, self.text):
                return True
        return False

    def _add_child(self, text, indent_level=None, alert_on_duplicate=False):
        """ Add a child instance of HierarchicalConfiguration """
        if alert_on_duplicate:
            if self._child_exists(text) and not self._duplicate_child_allowed_check():
                path = self._path() + [text]
                self.logger.warn(u"WARNING for {} - Found a duplicate section: {}".format(self.options['hostname'], path))
        if not self._child_exists(text) or (self.parent and self.parent._duplicate_child_allowed_check()):
            new_item = HierarchicalConfiguration(self, text, indent_level)
            self.children.append(new_item)
            return new_item
        else:
            # If the child is already present and the parent does not allow
            # duplicate children, return the existing child
            return self.get_child(text)

    def _add_shallow_copy_of(self, child_to_add):
        """ Add a nested copy of a child to self"""
        new_child = self._add_child(
            copy.copy(child_to_add.text),
            copy.copy(child_to_add.indent_level)
        )
        new_child.comment = copy.copy(child_to_add.comment)
        new_child.tags = copy.copy(child_to_add.tags)
        return new_child

    def _add_deep_copy_of(self, child_to_add):
        """ Add a nested copy of a child to self"""
        new_child = self._add_shallow_copy_of(child_to_add)
        for child in child_to_add.children:
            new_child._add_deep_copy_of(child)
        return new_child

    def _rename_child(self, old_text, new_text):
        """ Change a child's text """
        for child in self.children:
            if child.text == old_text:
                child.text = new_text
                break

    def _lineage(self):
        """
        Return the lineage of parent objects, up to but excluding the root
        """
        if self.parent:
            parents = self.parent._lineage()
            return parents + [self]
        else:
            return []

    def _path(self):
        """
        Return a list of the text instance variables from self.lineage
        """
        path = [c.text for c in self._lineage()]
        return path

    def _cisco_style_text(self):
        """ Return a Cisco style formated line i.e. indentation_level + text """
        #if not self.text:
        #    return None
        the_text = "{}{}".format(" " * self.indent_level, self.text)
        return the_text

    #We will worry about this later
    #def type_7_password_decrypt(self, text):
    #    decrypt=lambda x:''.join([chr(int(x[i:i+2],16)^ord('dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87'[(int(x[:2])+i/2-1)%53]))for i in range(2,len(x),2)])
    #    return decrypt(text)

    def _all_children(self):
        """ Recursively find and return all children """
        found_children = []
        for child in self.children:
            found_children += child._all_children()
        if self._is_base_instance():
            return found_children
        else:
            return [self] + found_children

    def _sectional_overwrite_no_negate_check(self):
        """
        Check self's text to see if negation should be handled by
        overwriting the section without first negating it
        """
        for line in self.options['sectional_overwrite_no_negate']:
            if re.match(line, self.text):
                return True
        return False

    def _sectional_overwrite_check(self):
        """ Determines if self.text matches a sectional overwrite rule """
        for line in self.options['sectional_overwrite']:
            if re.match(line, self.text):
                return True
        return False

    def _overwrite_with(self, other, delta, negate=True):
        """ Deletes delta.child[self.text], adds a deep copy of self to delta """
        if other.children != self.children:
            if negate:
                delta._del_child(self.text)
                deleted = delta._add_child(
                    self.text, self.indent_level)._negate()
                deleted.comment = "dropping entire section"
            if self.children:
                delta._del_child(self.text)
                new_item = delta._add_deep_copy_of(self)
                new_item.comment = "re-create section from scratch"
        return delta

    def _get_sectional_exiting_text(self):
        """
        Determine if self.text requires sectional exiting text and returns it.
        Else return False.
        """
        if not self.children or not self.parent:
            return False
        for item in self.options['sectional_exiting']:
            if re.search(item['parent_expression'], self.text):
                return item['exit_text']
        return False

    def add_sectional_exiting(self):
        """
        Adds the sectional exiting text as a child
        """
        for child in self.children:
            child.add_sectional_exiting()

        sectional_exit_text = self._get_sectional_exiting_text()
        if sectional_exit_text:
            if self._child_exists(sectional_exit_text):
                if len(self.children) > 1:
                    self._del_child(sectional_exit_text)
                    self._add_child(
                        sectional_exit_text, self._get_child_indent())
            else:
                self._add_child(
                    sectional_exit_text, self._get_child_indent())
        return self

    def _get_child_indent(self):
        """ Determines the child indent level and returns it """
        if self.children:
            return self.children[0].indent_level
        else:
            return self.indent_level + 1

    def to_tag_spec(self):
        """
        Returns the configuration as a tag spec definition
        This is handy when you have a segment of config and need to
        generate a tag spec to tag configuration in another instance
        """
        tag_spec = []
        for child in self._all_children():
            if not child.children:
                child_spec = [{'equals': t} for t in child._path()]
                tag_spec.append({'section': child_spec, 'action': 'add'})
        return tag_spec

    def add_tags(self, tag_rules):
        """
        Handler for tagging sections of HierarchicalConfiguration data structure
        for inclusion and exclusion.
        """
        for tag_name, rules in tag_rules.iteritems():
            for rule in rules:
                if rule['action'] == 'remove':
                    self._tag_deep_remove_by_section(copy.copy(rule['section']), tag_name)
                elif rule['action'] == 'add':
                    self._tag_deep_append_by_section(copy.copy(rule['section']), tag_name)

        return self

    def _tag_append_by_tag(self, tag):
        """
        Add tag from the tag list in self
        """
        if not tag in self.tags:
            self.tags.append(tag)

    def _tag_remove_by_tag(self, tag):
        """
        Remove tag from the tag list in self
        """
        if tag in self.tags:
            self.tags.remove(tag)

    def tag_deep_remove_by_tag(self, tag):
        """
        Remove tag from the tag list in self and recursively for all children
        This is used to clean up tags that have been added temporarily
        """
        self._tag_remove_by_tag(tag)
        for child in self.all_children:
            child._tag_remove_by_tag(tag)

    def _tag_deep_remove_by_section(self, section, tag):
        """
        Process a tag for exclusion
        """
        section_item = section.pop(0)
        for child in self.children:
            matches = 0
            for section_test, section_expression in section_item.iteritems():
                if section_test == 'new_in_config':
                    if child.new_in_config == section_expression:
                        matches += 1
                elif TextMatch.dict_call(section_test, child.text, section_expression):
                    matches += 1
            if matches == len(section_item.keys()):
                if section:
                    child._tag_deep_remove_by_section(copy.copy(section), tag)
                else:
                    child._tag_remove_by_tag(tag)
                    for sub_child in child._all_children():
                        sub_child._tag_remove_by_tag(tag)

    def _tag_deep_append_by_section(self, section, tag):
        """
        Process a tag for inclusion
        """
        section_item = section.pop(0)
        for child in self.children:
            matches = 0
            for section_test, section_expression in section_item.iteritems():
                if section_test == 'new_in_config':
                    if child.new_in_config == section_expression:
                        matches += 1
                elif TextMatch.dict_call(section_test, child.text, section_expression):
                    matches += 1
            if matches == len(section_item.keys()):
                if section:
                    child._tag_deep_append_by_section(copy.copy(section), tag)
                else:
                    child._tag_append_by_tag(tag)
                    for parent in child.parent._lineage():
                        parent._tag_append_by_tag(tag)
                    for sub_child in child._all_children():
                        sub_child._tag_append_by_tag(tag)

    def with_tags(self, tags, new_instance=None):
        """
        Returns a new instance containing only sub-objects
        with one of the tags in tags
        """
        if new_instance is None:
            new_instance = HierarchicalConfiguration(options=self.options)

        for child in self.children:
            if list(set(tags) & set(self.tags)):
                new_instance._add_shallow_copy_of(child)
                new_child.with_tags(tags, new_child)

        return new_instance

    def deep_diff_tree_with(self, other, delta=None):
        """
        Figures out what commands need to be executed to transition from other to self.
        Self is the targat datastructure(i.e. the compiled template), other is the source(i.e. running-config)
        """

        if delta == None:
            delta = HierarchicalConfiguration(options=self.options)

        # find other.children that are not in self.children - i.e. what needs to be negated or defaulted
        #   Also, find out if another command in other.children will overwrite - i.e. be idempotent
        for other_child in other.children:
            if self._child_exists(other_child.text):
                pass
            elif other_child._idempotent_command(self.children):
                pass
            else:
                # in other but not self
                # add this node but not any children
                deleted = delta._add_child(
                    other_child.text, other_child.indent_level)
                deleted._negate()
                if other_child.children:
                    deleted.comment = "removes {} lines".format(
                        len(other_child._all_children()) + 1)

        # find what would need to be added to other to get to self
        for self_child in self.children:
            # if the child exist, recurse into its children 
            if other._child_exists(self_child.text):
                other_child = other.get_child(self_child.text)
                subtree = delta._add_child(self_child.text, self_child.indent_level)
                self_child.deep_diff_tree_with(other_child, subtree)
                if not subtree.children:
                    subtree._delete()
                # Do we need to rewrite the child and its children as well?
                elif other_child._sectional_overwrite_check():
                    self_child._overwrite_with(other_child, delta, True)
                elif other_child._sectional_overwrite_no_negate_check():
                    self_child._overwrite_with(other_child, delta, False)
            # if the child is absent, add it
            else:
                new_item = delta._add_deep_copy_of(self_child)
                # mark the new item and all of its children as new_in_config
                for child in new_item._all_children():
                    child.new_in_config = True
                if new_item.children:
                    new_item.comment = "new section, didn't exist before"

        return delta

    def from_file(self, file_path):
        """ Load configuration text from a file """
        with open(file_path, 'r') as f:
            config_text = f.read()
        self.from_config_text(config_text)

    def from_config_text(self, config_text):
        """ Create HierarchicalConfiguration nested objects from text """
        for sub in self.options['full_text_sub']:
            config_text = re.sub(sub['search'].decode(
                'string_escape'), sub['replace'].decode('string_escape'), config_text)

        config = self
        current_section = self
        current_section.indent_level = -1
        most_recent_item = current_section
        indent_adjust = 0
        end_indent_adjust = []

        for line in config_text.splitlines():
            line = line.rstrip('\n')
            for sub in self.options['per_line_sub']:
                line = re.sub(
                        sub['search'].decode('string_escape'),
                        sub['replace'].decode('string_escape'),
                        line)
            line = line.rstrip()

            # If line is now empty, move to the next
            if not line:
                continue

            # Determine indentation level
            this_indent = len(line) - len(line.lstrip()) + indent_adjust

            line = line.lstrip()

            # Walks back up the tree
            while this_indent <= current_section.indent_level:
                current_section = current_section.parent

            # Walks down the tree by one step
            if this_indent > most_recent_item.indent_level:
                current_section = most_recent_item

            most_recent_item = current_section._add_child(
                line, this_indent, True)

            for expression in self.options['indent_adjust']:
                if re.search(expression['start_expression'], line):
                    indent_adjust += 1
                    end_indent_adjust.append(expression['end_expression'])
                    break
            if end_indent_adjust and re.search(end_indent_adjust[0], line):
                indent_adjust -= 1
                del(end_indent_adjust[0])

        return config

    def to_detailed_ouput(self):
        """ Returns a list of Cisco style formated lines with tags and comments"""
        lines = []
        for child in self._all_children():
            cisco_style_text_line = child._cisco_style_text()
            #if cisco_style_text_line is None:
            #    continue
            lines.append({
                'text': cisco_style_text_line,
                'tags': child.tags,
                'comment': child.comment
                })

        return lines

    def _negate(self):
        """ Negate self.text """
        old_text = self.text
        done = False

        for rule in self.options['negation_negate_with']:
            if re.match(rule['match'], self.text):
                self.text = rule['use']
                done = True
                break

        if not done:
            for expression in self.options['negation_default_when']:
                if re.match(expression, self.text):
                    if self.text.startswith('no '):
                        self.text = self.text[3:]
                    self.text = "default {}".format(self.text)
                    done = True
                    break

        if not done:
            if self.text.startswith('no '):
                #removes 'no '
                self.text = self.text[3:]
            else:
                #appends 'no '
                self.text = 'no ' + self.text

        if self.parent:
            self.parent._rename_child(old_text, self.text)
        return self

    def _idempotent_acl_iosxr_check(self):
        """ Handle conditional testing to determine if idempotent acl handling for iosxr should be used """
        if 'idempotent_acl_iosxr' in self.options and self.options['idempotent_acl_iosxr']:
            if not self.parent._is_base_instance():
                if self.parent.text.startswith('ipv4 access-list'):
                    return True
                elif self.parent.text.startswith('ipv6 access-list'):
                    return True
        return False

    def _idempotent_command(self, other_children):
        """
        Determine if self.text is an idempotent change.
        list of commands(expressions) that are overwritable by commands that match the same expressions
        """

        # Blacklist commands from matching as idempotent
        for expression in self.options['idempotent_commands_blacklist']:
            if re.search(expression, self.text):
                return False

        # Handles idempotent acl entry identification 
        if self._idempotent_acl_iosxr_check():
            self_sn = self.text.split(' ', 1)[0]
            for other_child in other_children:
                other_sn = other_child.text.split(' ', 1)[0]
                if self_sn == other_sn:
                    return True

        # Expression based idempotent command identification
        for expression in self.options['idempotent_commands']:
            expression = "^(?:no )?({})".format(expression)
            if re.search(expression, self.text):
                for other_child in other_children:
                    if re.search(expression, other_child.text):
                        return True

        return False
