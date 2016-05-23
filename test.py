import yaml
from hierarchical_configuration import HierarchicalConfiguration

class HierTest(object):

    def __init__(self, running_config, compiled_config):
        self.hier_options = self._load_hier_options()
        self.hier_tags = self._load_hier_tags()
        self.running_config_hier = self._load_running_config(running_config)
        self.compiled_config_hier = self._load_compiled_config(compiled_config)

    def _load_hier_options(self):
        """
        load the appropriate HierarchicalConfiguration options
        """
        with open('main.yml', 'r') as my_file:
            hier_options = yaml.load(my_file)['hier_options']

        return hier_options

    def _load_hier_tags(self):
        """
        Load the appropriate HierarchicalConfiguration tag definitions
        """
        with open('main.yml', 'r') as my_file:
            hier_tags = yaml.load(my_file)['hier_tags']

        return hier_tags

    def _load_running_config(self, running_config):
        """
        Build HierarchicalConfiguration object for the Running Config
        """
        running_config_hier = HierarchicalConfiguration(
            options=self.hier_options)
        running_config_hier.from_config_text(running_config)

        return running_config_hier

    def _load_compiled_config(self, compiled_config):
        """
        Build HierarchicalConfiguration object for the Compiled Config
        """
        compiled_config_hier = HierarchicalConfiguration(
            options=self.hier_options)
        compiled_config_hier.from_config_text(compiled_config)

        return compiled_config_hier

    def build_remediation(self):
        """
        Build HierarchicalConfiguration object for the Remediation Config
        """
        remediation_config_hier = self.compiled_config_hier.deep_diff_tree_with(self.running_config_hier)
        remediation_config_hier.set_order_weight()
        remediation_config_hier.add_sectional_exiting()
        remediation_config_hier.add_tags(self.hier_tags)

        return remediation_config_hier.to_detailed_ouput()

with open('running_config', 'r') as myfile:
    running_config = ''
    for line in myfile.readlines():
        running_config += line + '\n'

with open('compiled_config', 'r') as myfile:
    compiled_config = ''
    for line in myfile.readlines():
        compiled_config += line + '\n'

hier = HierTest(running_config, compiled_config)

for line in hier.build_remediation():
    print line['text']
