import re
import sys
import copy
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
      - lineage:
        - startswith: snmp
        action: add
      - lineage:
        - contains: ACL-VTY-IP
        action: add
      - lineage:
        - equals: policy-map INFRA_L3VPN
        action: add
      - lineage:
        - startswith: router bgp
        - startswith: neighbor-group
        - startswith: address-family
        - re_search: route-policy (DENY|DROP)
        action: add
      - lineage:
        - startswith: interface
        - equals: no carrier-delay up 0 down 0
        action: add
      pacl:
      - lineage:
        - startswith: ipv4 access-list pacl_ipv4
        action: add
      - lineage:
        - startswith: ipv6 access-list pacl_ipv6
        action: add
    """

    def __init__(
            self, parent=None, text=None, indent_level=None, options=None):

        if text is None:
            self.text = text
        else:
            self.text = text.strip()

        self.parent = parent
        if self._is_base_instance():
            self.indent_level = -1
            self.options = options
            self.logs = list()
        else:
            self.indent_level = indent_level
            self.options = self.parent.options
            self.logs = self.parent.logs

        self.children = []
        # The intent is for self.order_weight values to range from 1 to 999
        # with the default weight being 500
        self.order_weight = 500
        self.tags = []
        self.comment = ''
        self.post_exec_sleep = 0
        self.post_exec_string = ''
        self.new_in_config = False

    def __repr__(self):
        return 'HierarchicalConfiguration({}, {})'.format(
            self.text,
            self.indent_level)

    def __str__(self):
        return self.text

    def __lt__(self, other):
        if self.order_weight < other.order_weight:
            return True
        else:
            return False

    def _is_base_instance(self):
        """ Check if this instance is the base instance in the hierarchy """
        if self.parent is None:
            return True
        else:
            return False

    def _delete(self):
        """ Delete the current object from its parent """
        self.parent.children[:] = [
            c for c in self.parent.children if not id(self) == id(c)]

    def _child_exists(self, text):
        """ Determine if child exists given the text of the child """
        for child in self.children:
            if child.text == text:
                return True
        return False

    def get_child(self, test, expression):
        """ Find a child by TextMatch rule. If it is not found, return None """
        children = self.get_children(test, expression)
        if children:
            return children[0]
        else:
            return None

    def get_children(self, test, expression):
        """ Find all children matching a TextMatch rule and return them. """

        matching_children = list()
        for child in self.children:
            if TextMatch.dict_call(test, child.text, expression):
                matching_children.append(child)
        return matching_children

    def del_child(self, text):
        """ Delete all children with the provided text """
        self.children[:] = [c for c in self.children if c.text != text]

    @staticmethod
    def _lineage_eval_object_rules(rules, section):
        """
        Evaluate a list of lineage object rules.
        All object rules must match in order to return True
        """
        matches = 0
        for rule in rules:
            if rule['test'] == 'new_in_config':
                if rule['expression'] == section.new_in_config:
                    matches += 1
            elif rule['test'] == 'negative_intersection_tags':
                if isinstance(rule['expression'], basestring):
                    rule['expression'] = [rule['expression']]
                if not set(rule['expression']).intersection(section.tags):
                    matches += 1
        if matches == len(rules):
            return True
        else:
            return False

    @staticmethod
    def _lineage_eval_text_match_rules(rules, text):
        """
        Evaluate a list of lineage text_match rules.
        Only one text_match rule must match in order to return True
        """
        for rule in rules:
            if TextMatch.dict_call(rule['test'], text, rule['expression']):
                return True
        return False

    @staticmethod
    def _explode_lineage_rule(rule):
        text_match_rules = list()
        object_rules = list()
        for k, v in rule.iteritems():
            if k in ['new_in_config', 'negative_intersection_tags']:
                object_rules.append({'test': k, 'expression': v})
            elif isinstance(v, list):
                text_match_rules += [{'test': k, 'expression': e} for e in v]
            else:
                text_match_rules += [{'test': k, 'expression': v}]
        return(object_rules, text_match_rules)

    def _lineage_test(self, rule, strip_negation=False):
        """ A generic test against a lineage of HierarchicalConfiguration objects """
        lineage = self._lineage()
        if rule['lineage'] and 'match_leaf' in rule[
                'lineage'][0] and rule['lineage'][0]['match_leaf']:
            lineage = [lineage[-1]]
            del(rule['lineage'][0]['match_leaf'])

        if 'debug' in rule and rule['debug']:
            debug = True
        else:
            debug = False

        if not len(rule['lineage']) == len(lineage):
            return False

        matches = 0
        if debug:
            print "lineage_rule ", rule['lineage']
            print "lineage ", [l.text for l in lineage]

        for lineage_rule, section in zip(rule['lineage'], lineage):
            object_rules, text_match_rules = HierarchicalConfiguration._explode_lineage_rule(
                lineage_rule)
            if debug:
                print "lineage_rule ", lineage_rule
                print "section.text ", section.text

            if not HierarchicalConfiguration._lineage_eval_object_rules(
                    object_rules, section):
                if debug:
                    print "object rule failed and fully failed"
                    print "  section.new_in_config", section.new_in_config
                    print "  section.tags", section.tags
                return False
            else:
                if debug:
                    print "object rule passed"

            # This removes negations for each section but honestly,
            # we really only need to do this on the last one
            if strip_negation:
                if section.text.startswith('no '):
                    text = section.text[3:]
                elif section.text.startswith('default '):
                    text = section.text[8:]
                else:
                    text = section.text
            else:
                text = section.text

            if HierarchicalConfiguration._lineage_eval_text_match_rules(
                    text_match_rules, text):
                matches += 1
                if debug:
                    print "rule text_match passed"
                continue
            else:
                if debug:
                    print "rule text_match failed and fully failed"
                return False

        if matches == len(rule['lineage']):
            if debug:
                print "rule fully passed"
            return True
        else:
            if debug:
                print "rule fully failed"
            return False

    def _duplicate_child_allowed_check(self):
        """ Determine if duplicate(identical text) children are allowed under the parent """
        for rule in self.options['parent_allows_duplicate_child']:
            if self._lineage_test(rule):
                return True
        return False

    def add_child(
            self, text, indent_level=None, alert_on_duplicate=False, idx=None):
        if idx is None:
            idx = len(self.children)
        """ Add a child instance of HierarchicalConfiguration """
        if not self._child_exists(text):
            new_item = HierarchicalConfiguration(self, text, indent_level)
            self.children.insert(idx, new_item)
            return new_item
        elif self._duplicate_child_allowed_check():
            new_item = HierarchicalConfiguration(self, text, indent_level)
            self.children.insert(idx, new_item)
            return new_item
        else:
            # If the child is already present and the parent does not allow
            # duplicate children, return the existing child
            if alert_on_duplicate:
                path = self._path() + [text]
                self.logs.append("Found a duplicate section: {}".format(path))
            return self.get_child('equals', text)

    def _add_shallow_copy_of(self, child_to_add):
        """ Add a nested copy of a child to self"""
        new_child = self.add_child(
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
        the_text = "{}{}".format(" " * self.indent_level, self.text)
        return the_text

    # We will worry about this later
    # def type_7_password_decrypt(self, text):
    #    decrypt=lambda x:''.join([chr(int(x[i:i+2],16)^ord('dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87'[(int(x[:2])+i/2-1)%53]))for i in range(2,len(x),2)])
    #    return decrypt(text)

    def _all_children_sorted(self):
        """ Recursively find and return all children sorted at each hierarchy """
        found_children = []
        for child in sorted(self.children):
            found_children += child._all_children_sorted()
        if self._is_base_instance():
            return found_children
        else:
            return [self] + found_children

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
        for rule in self.options['sectional_overwrite_no_negate']:
            if self._lineage_test(rule):
                return True
        return False

    def _sectional_overwrite_check(self):
        """ Determines if self.text matches a sectional overwrite rule """
        for rule in self.options['sectional_overwrite']:
            if self._lineage_test(rule):
                return True
        return False

    def _resequence_acl_check(self):
        """
        Is the object an ACL and is ACL resequencing enabled
        """
        if self.options['style'] in ['ios']:
            acl_sw = ('ip access-list')
            if self.text.startswith(acl_sw):
                return True
        return False

    def _resequence_acl(self, delta):
        """ Inserts an ACL resequence command """
        acl_name = self.text.split(' ')[3]

        for idx, child in enumerate(delta.children):
            if child.text == self.text:
                index = idx
                break
        resquence = delta.add_child(
            "ip access-list resequence {} 10 10".format(acl_name),
            self.indent_level,
            idx=index
        )
        resquence.comment = "added acl resequence"
        return delta

    def _overwrite_with(self, other, delta, negate=True):
        """ Deletes delta.child[self.text], adds a deep copy of self to delta """
        if other.children != self.children:
            if negate:
                delta.del_child(self.text)
                deleted = delta.add_child(
                    self.text, self.indent_level).negate()
                deleted.comment = "dropping entire section"
            if self.children:
                delta.del_child(self.text)
                new_item = delta._add_deep_copy_of(self)
                new_item.comment = "re-create section from scratch"
        return delta

    def set_order_weight(self):
        """
        Sets self.order integer on all children
        """
        for child in self._all_children():
            for rule in self.options['ordering']:
                if child._lineage_test(rule):
                    child.order_weight = rule['order']

    def add_sectional_exiting(self):
        """
        Adds the sectional exiting text as a child
        """
        for child in self._all_children():
            for rule in self.options['sectional_exiting']:
                if child._lineage_test(rule):
                    if child._child_exists(rule['exit_text']):
                        child.del_child(rule['exit_text'])

                    new_child = child.add_child(
                        rule['exit_text'],
                        child._get_child_indent()
                    )
                    new_child.order_weight = 999

    def _get_child_indent(self):
        """ Determines the child indent level and returns it """
        if self.children:
            return self.children[0].indent_level
        else:
            return self.indent_level + 1

    def to_tag_spec(self, tags):
        """
        Returns the configuration as a tag spec definition
        This is handy when you have a segment of config and need to
        generate a tag spec to tag configuration in another instance
        """
        tag_spec = []
        for child in self._all_children():
            if not child.children:
                child_spec = [{'equals': t} for t in child._path()]
                tag_spec.append({'section': child_spec, 'add_tags': tags})
        return tag_spec

    def add_tags(self, tag_rules, strip_negation=False):
        """
        Handler for tagging sections of HierarchicalConfiguration data structure
        for inclusion and exclusion.
        """
        for rule in tag_rules:
            for child in self._all_children():
                if child._lineage_test(rule, strip_negation):
                    if 'add_tags' in rule:
                        child.deep_append_tags(rule['add_tags'])
                        for ancestor in child.parent._lineage():
                            ancestor._append_tags(rule['add_tags'])
                    if 'remove_tags' in rule:
                        child.deep_remove_tags(rule['remove_tags'])

        return self

    def deep_append_tags(self, tags):
        """
        Append tags to self.tags and recursively for all children
        """
        self._append_tags(tags)
        for child in self._all_children():
            child._append_tags(tags)

    def deep_remove_tags(self, tags):
        """
        Remove tags from self.tags and recursively for all children
        """
        self._remove_tags(tags)
        for child in self._all_children():
            child._remove_tags(tags)

    def _append_tags(self, tags):
        """
        Add tags to self.tags
        """
        if isinstance(tags, basestring):
            tags = [tags]
        for tag in tags:
            if not tag in self.tags:
                self.tags.append(tag)

    def _remove_tags(self, tags):
        """
        Remove tags from self.tags
        """
        if isinstance(tags, basestring):
            tags = [tags]
        for tag in tags:
            if tag in self.tags:
                self.tags.remove(tag)

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

        if delta is None:
            delta = HierarchicalConfiguration(options=self.options)

        # find other.children that are not in self.children - i.e. what needs to be negated or defaulted
        # Also, find out if another command in other.children will overwrite -
        # i.e. be idempotent
        for other_child in other.children:
            if self._child_exists(other_child.text):
                pass
            elif other_child._idempotent_command(self.children):
                pass
            else:
                # in other but not self
                # add this node but not any children
                deleted = delta.add_child(
                    other_child.text,
                    other_child.indent_level)
                deleted.negate()
                if other_child.children:
                    deleted.comment = "removes {} lines".format(
                        len(other_child._all_children()) + 1)

        # find what would need to be added to other to get to self
        for self_child in self.children:
            # if the child exist, recurse into its children
            if other._child_exists(self_child.text):
                other_child = other.get_child('equals', self_child.text)
                subtree = delta.add_child(
                    self_child.text,
                    self_child.indent_level)
                self_child.deep_diff_tree_with(other_child, subtree)
                if not subtree.children:
                    subtree._delete()
                # If the line is an ACL, do we need to resequence it?
                elif other_child._resequence_acl_check():
                    self_child._resequence_acl(delta)
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

    def _add_acl_sequence_numbers(self):
        """
        Add ACL sequence numbers for use on configurations with a style of 'ios'
        """

        ipv4_acl_sw = ('ip access-list')
        #ipv6_acl_sw = ('ipv6 access-list')
        acl_line_sw = ('permit', 'deny', 'remark')
        for child in self.children:
            if child.text.startswith(ipv4_acl_sw):
                sn = 10
                for sub_child in child.children:
                    if sub_child.text.startswith(acl_line_sw):
                        sub_child.text = "{} {}".format(sn, sub_child.text)
                        sn += 10
            # elif child.text.startswith(ipv6_acl_sw):
            #    sn = 10
            #    for sub_child in child.children:
            #        if sub_child.text.startswith(acl_line_sw):
            #            sub_child.text = "sequence {} {}".format(sn, sub_child.text)
            #            sn += 10
        return self

    def from_config_text(self, config_text):
        """ Create HierarchicalConfiguration nested objects from text """
        for sub in self.options['full_text_sub']:
            config_text = re.sub(
                sub['search'].decode(
                    'string_escape'),
                sub['replace'].decode(
                    'string_escape'),
                config_text)

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

            most_recent_item = current_section.add_child(
                line,
                this_indent,
                True)

            for expression in self.options['indent_adjust']:
                if re.search(expression['start_expression'], line):
                    indent_adjust += 1
                    end_indent_adjust.append(expression['end_expression'])
                    break
            if end_indent_adjust and re.search(end_indent_adjust[0], line):
                indent_adjust -= 1
                del(end_indent_adjust[0])

        if self.options['style'] in ['ios']:
            self._add_acl_sequence_numbers()

        return self

    def to_detailed_ouput(self):
        """ Returns a list of Cisco style formated lines with tags and comments"""
        lines = []
        for child in self._all_children_sorted():
            cisco_style_text_line = child._cisco_style_text()
            lines.append({
                'text': cisco_style_text_line,
                'tags': child.tags,
                'post_exec_sleep': child.post_exec_sleep,
                'post_exec_string': child.post_exec_string,
                'comment': child.comment
            })

        return lines

    def _swap_negation(self):
        """ Swap negation of a self.text """
        if self.text.startswith('no '):
            self.text = self.text[3:]
        else:
            self.text = 'no ' + self.text
        return self

    def _default(self):
        """ Default self.text """
        if self.text.startswith('no '):
            self.text = 'default ' + self.text[3:]
        else:
            self.text = 'default ' + self.text
        return self

    def negate(self):
        """ Negate self.text """
        for rule in self.options['negation_negate_with']:
            if self._lineage_test(rule):
                self.text = rule['use']
                return self

        for rule in self.options['negation_default_when']:
            if self._lineage_test(rule):
                return self._default()

        return self._swap_negation()

    def _idempotent_acl_check(self):
        """
        Handle conditional testing to determine if idempotent acl handling for iosxr should be used
        """
        if self.options['style'] in ['iosxr']:
            if not self.parent._is_base_instance():
                acl = ('ipv4 access-list', 'ipv6 access-list')
                if self.parent.text.startswith(acl):
                    return True
        return False

    def _idempotent_command(self, other_children):
        """
        Determine if self.text is an idempotent change.
        """

        # Blacklist commands from matching as idempotent
        for rule in self.options['idempotent_commands_blacklist']:
            if self._lineage_test(rule, True):
                return False

        # Handles idempotent acl entry identification
        if self._idempotent_acl_check():
            if self.options['style'] in ['iosxr']:
                self_sn = self.text.split(' ', 1)[0]
            for other_child in other_children:
                if self.options['style'] in ['iosxr']:
                    other_sn = other_child.text.split(' ', 1)[0]
                if self_sn == other_sn:
                    return True

        # Idempotent command identification
        for rule in self.options['idempotent_commands']:
            if self._lineage_test(rule, True):
                for other_child in other_children:
                    if other_child._lineage_test(rule, True):
                        return True

        return False
