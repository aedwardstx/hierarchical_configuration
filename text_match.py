import re


class TextMatch(object):

    """
    Provides a suite of text matching methods
    """

    @classmethod
    def dict_call(cls, test, text, expression):
        """
        Allows test methods to be called easily from variables
        """
        return {
            'equals': cls.equals,
            'startswith': cls.startswith,
            'endswith': cls.endswith,
            'contains': cls.contains,
            're_search': cls.re_search
        }[test](text, expression)

    @staticmethod
    def equals(text, expression):
        """Text equivalence test"""
        return text == expression

    @staticmethod
    def startswith(text, expression):
        """Text starts with test"""
        return text.startswith(expression)

    @staticmethod
    def endswith(text, expression):
        """Text ends with test"""
        return text.endswith(expression)

    @staticmethod
    def contains(text, expression):
        """Text contains test"""
        return expression in text

    @staticmethod
    def re_search(text, expression):
        """
        Test regex match. This method is comparatively
        very slow and should be avoided where possible.
        """
        return re.search(expression, text) is not None
