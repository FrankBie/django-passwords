from __future__ import division
from __future__ import with_statement
import string

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import smart_unicode
from django.conf import settings

COMMON_SEQUENCES = [
    "0123456789",
    "`1234567890-=",
    "~!@#$%^&*()_+",
    "abcdefghijklmnopqrstuvwxyz",
    "quertyuiop[]\\asdfghjkl;\'zxcvbnm,./",
    'quertyuiop{}|asdfghjkl;"zxcvbnm<>?',
    "quertyuiopasdfghjklzxcvbnm",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]\\",
    "qazwsxedcrfvtgbyhnujmikolp"
]

# Settings
PASSWORD_MIN_LENGTH = getattr(settings, "PASSWORD_MIN_LENGTH", 6)
PASSWORD_MAX_LENGTH = getattr(settings, "PASSWORD_MAX_LENGTH", None)
PASSWORD_MAX_COMMON_SUBSTRING_LENGTH = getattr(settings, "PASSWORD_MAX_COMMON_SUBSTRING_LENGTH", 4)
PASSWORD_DICTIONARY = getattr(settings, "PASSWORD_DICTIONARY", None)
PASSWORD_MATCH_THRESHOLD = getattr(settings, "PASSWORD_MATCH_THRESHOLD", 0.9)
PASSWORD_COMMON_SEQUENCES =  getattr(settings, "PASSWORD_COMMON_SEQUENCES", COMMON_SEQUENCES)
PASSWORD_COMPLEXITY = getattr(settings, "PASSWORD_COMPLEXITY", None)

class LengthValidator(object):
    message = _("Invalid Length (%s)")
    code = "length"

    def __init__(self, min_length=None, max_length=None):
        self.min_length = min_length
        self.max_length = max_length

    def __call__(self, value):
        if self.min_length and len(value) < self.min_length:
            raise ValidationError(
                "Password is too short."
            )
        elif self.max_length and len(value) > self.max_length:
            raise ValidationError(
                "Password is too long."
            )

class ComplexityValidator(object):
    message = _("Must be more complex (%s)")
    code = "complexity"

    def __init__(self, complexities):
        self.complexities = complexities

    def __call__(self, value):
        if self.complexities is None:
            return

        uppercase, lowercase, digits, non_ascii, punctuation = set(), set(), set(), set(), set()

        for character in value:
            if ord(character) >= 128:
                non_ascii.add(character)
            elif character.isupper():
                uppercase.add(character)
            elif character.islower():
                lowercase.add(character)
            elif character.isdigit():
                digits.add(character)
            elif character in string.punctuation:
                punctuation.add(character)
            else:
                non_ascii.add(character)

        words = set(value.split())

        if len(uppercase) < self.complexities.get("UPPER", 0):
            raise ValidationError(
                "Must contain more uppercase characters."
            )
        elif len(lowercase) < self.complexities.get("LOWER", 0):
            raise ValidationError(
                "Must contain more lowercase characters."
            )
        elif len(digits) < self.complexities.get("DIGITS", 0):
            raise ValidationError(
                "Must contain more digits."
            )
        elif len(punctuation) < self.complexities.get("PUNCTUATION", 0):
            raise ValidationError(
                "Must contain more punctuation."
            )
        elif len(non_ascii) < self.complexities.get("NON ASCII", 0):
            raise ValidationError(
                "Must contain more symbol characters."
            )
        elif len(words) < self.complexities.get("WORDS", 0):
            raise ValidationError(
                "Must contain more unique words."
            )


class BaseSimilarityValidator(object):
    message = _("Too Similar to [%(haystacks)s]")
    code = "similarity"

    def __init__(self, haystacks=None):
        self.haystacks = haystacks if haystacks else []

    def fuzzy_substring(self, needle, haystack):
        needle, haystack = needle.lower(), haystack.lower()
        m, n = len(needle), len(haystack)

        if m == 1:
            if not needle in haystack:
                return -1
        if not n:
            return m

        row1 = [0] * (n+1)
        for i in xrange(0,m):
            row2 = [i+1]
            for j in xrange(0,n):
                cost = ( needle[i] != haystack[j] )
                row2.append(min(row1[j+1]+1, row2[j]+1, row1[j]+cost))
            row1 = row2
        return min(row1)

    def __call__(self, value):
        for haystack in self.haystacks:
            distance = self.fuzzy_substring(value, haystack)
            longest = max(len(value), len(haystack))
            similarity = (longest - distance) / longest
            if similarity >= PASSWORD_MATCH_THRESHOLD:
                raise ValidationError(
                    self.message % {"haystacks": ", ".join(self.haystacks)},
                    code=self.code)

class DictionaryValidator(BaseSimilarityValidator):
    message = _("Password is based on a dictionary word.")
    code = "dictionary_word"

    def __init__(self, words=None, dictionary=None):
        haystacks = []
        if dictionary:
            with open(dictionary) as dictionary:
                haystacks.extend(
                    [smart_unicode(x.strip()) for x in dictionary.readlines()]
                )
        if words:
            haystacks.extend(words)
        super(DictionaryValidator, self).__init__(haystacks=haystacks)


class CommonSequenceValidator(BaseSimilarityValidator):
    message = _("Password is based on a common sequence of characters.")
    code = "common_sequence"

class CommonSubStringValidator(object):
    message = _("Too Similar to %(haystacks)s")
    code = "common_substring"

    def __init__(self, haystacks=None):
        self.haystacks = haystacks if haystacks else []

    def longest_common_substring(self, needle, haystack):
        # source wikipedia
        # http://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Longest_common_substring
        m = [[0] * (1 + len(haystack)) for i in xrange(1 + len(needle))]
        longest, x_longest = 0, 0
        for x in xrange(1, 1 + len(needle)):
            for y in xrange(1, 1 + len(haystack)):
                if needle[x - 1] == haystack[y - 1]:
                    m[x][y] = m[x - 1][y - 1] + 1
                    if m[x][y] > longest:
                        longest = m[x][y]
                        x_longest = x
                else:
                    m[x][y] = 0
        return needle[x_longest - longest: x_longest]

    def __call__(self, value):
        for haystack in self.haystacks:
            a_common_substring = self.longest_common_substring(value, haystack)
            if len(a_common_substring) >= PASSWORD_MAX_COMMON_SUBSTRING_LENGTH:
                raise ValidationError(
                    self.message % {"haystacks": "".join(a_common_substring)},
                    code=self.code)


validate_length = LengthValidator(PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)
complexity = ComplexityValidator(PASSWORD_COMPLEXITY)
dictionary_words = DictionaryValidator(dictionary=PASSWORD_DICTIONARY)
common_sequences = CommonSequenceValidator(PASSWORD_COMMON_SEQUENCES)
common_substring = CommonSubStringValidator(PASSWORD_COMMON_SEQUENCES)