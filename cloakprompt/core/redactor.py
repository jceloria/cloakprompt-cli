"""
Text redactor for cloakprompt.

This module handles the actual redaction of sensitive information from text
using regex patterns loaded from configuration files.
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Optional, TypedDict
from .parser import ConfigParser

logger = logging.getLogger(__name__)


# Type definitions for better type checking
class MatchInfo(TypedDict):
    """Type definition for match information."""
    start: int
    end: int
    placeholder: str
    name: str
    matched_text: str


class TextRedactor:
    """Redacts sensitive information from text using regex patterns."""

    def __init__(self, config_parser: ConfigParser):
        """
        Initialize the text redactor.

        Args:
            config_parser: Configuration parser instance
        """
        self.config_parser = config_parser
        self.compiled_patterns: List[Tuple[re.Pattern, str, str]] = []
        self._compile_patterns()

    def _compile_patterns(self, custom_config_path: Optional[str] = None) -> None:
        """
        Compile regex patterns for efficient matching.

        Args:
            custom_config_path: Optional path to custom configuration file
        """
        patterns: List[Dict[str, Any]] = self.config_parser.get_regex_patterns(custom_config_path)
        self.compiled_patterns.clear()

        for pattern_info in patterns:
            try:
                # Compile the regex pattern
                compiled_regex = re.compile(pattern_info['regex'], re.IGNORECASE | re.MULTILINE)
                placeholder = pattern_info['placeholder']
                name = pattern_info['name']

                self.compiled_patterns.append((compiled_regex, placeholder, name))
                logger.debug(f"Compiled pattern '{name}': {pattern_info['regex']}")

            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_info.get('name', 'unknown')}': {e}")
                continue

        logger.info(f"Successfully compiled {len(self.compiled_patterns)} regex patterns")

    def _find_all_matches(self, text: str) -> List[MatchInfo]:
        """
        Find all matches from all compiled patterns.

        Args:
            text: Text to search for matches

        Returns:
            List of match dictionaries sorted by position and length
        """
        all_matches: List[MatchInfo] = []
        for pattern, placeholder, name in self.compiled_patterns:
            try:
                for match in pattern.finditer(text):
                    all_matches.append({
                        'start': match.start(),
                        'end': match.end(),
                        'placeholder': placeholder,
                        'name': name,
                        'matched_text': match.group()
                    })
            except Exception as e:
                logger.warning(f"Error applying pattern '{name}': {e}")
                continue

        # Sort by start position (ascending) and then by match length (descending)
        # This ensures longer matches (that might contain shorter ones) are processed first
        all_matches.sort(key=lambda x: (x['start'], -(x['end'] - x['start'])))
        return all_matches

    def redact_text(self, text: str, custom_config_path: Optional[str] = None) -> str:
        """
        Redact sensitive information from the given text.

        Args:
            text: Input text to redact
            custom_config_path: Optional path to custom configuration file

        Returns:
            Text with sensitive information redacted
        """
        if custom_config_path:
            # Recompile patterns if custom config is provided
            self._compile_patterns(custom_config_path)

        if not text:
            return text

        # Find all matches
        all_matches = self._find_all_matches(text)

        # Apply replacements, handling overlaps
        redacted_parts: List[str] = []
        last_pos = 0

        for match in all_matches:
            # Skip overlapping matches (matches that start before the last replacement ended)
            if match['start'] < last_pos:
                logger.debug(f"Skipping overlapping match for pattern '{match['name']}' "
                             f"at positions {match['start']}-{match['end']}")
                continue

            # Add text before this match
            redacted_parts.append(text[last_pos:match['start']])

            # Add the placeholder for this match
            redacted_parts.append(match['placeholder'])

            # Update last position
            last_pos = match['end']

        # Add any remaining text after the last match
        redacted_parts.append(text[last_pos:])
        redacted_text = ''.join(redacted_parts)

        if all_matches:
            actual_redactions = len([m for m in all_matches if m['start'] >= last_pos])
            logger.info(f"Found {len(all_matches)} total matches, applied {actual_redactions} redactions")

        return redacted_text

    def redact_with_details(self, text: str, custom_config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Redact text and return detailed information about what was redacted.

        Args:
            text: Input text to redact
            custom_config_path: Optional path to custom configuration file

        Returns:
            Dictionary containing redacted text and redaction details
        """
        # Get patterns based on config
        patterns: List[Dict[str, Any]] = self.config_parser.get_regex_patterns(custom_config_path)

        # Compile patterns locally for this operation
        compiled_patterns: List[Tuple[re.Pattern, str, str]] = []
        for pattern_info in patterns:
            try:
                compiled_regex = re.compile(pattern_info['regex'], re.IGNORECASE | re.MULTILINE)
                compiled_patterns.append((compiled_regex, pattern_info['placeholder'], pattern_info['name']))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_info.get('name', 'unknown')}': {e}")
                continue

        if not text:
            return {
                'redacted_text': text,
                'redactions': [],
                'total_redactions': 0
            }

        # Find all matches
        all_matches: List[MatchInfo] = []
        for pattern, placeholder, name in compiled_patterns:
            try:
                for match in pattern.finditer(text):
                    all_matches.append({
                        'start': match.start(),
                        'end': match.end(),
                        'placeholder': placeholder,
                        'name': name,
                        'matched_text': match.group()
                    })
            except Exception as e:
                logger.warning(f"Error applying pattern '{name}': {e}")
                continue

        # Sort matches by start position (ascending) and then by match length (descending)
        all_matches.sort(key=lambda x: (x['start'], -(x['end'] - x['start'])))

        # Apply replacements, handling overlaps
        redacted_text_parts: List[str] = []
        redactions: List[Dict[str, Any]] = []
        last_pos = 0

        for m in all_matches:
            # Skip overlapping matches
            if m['start'] < last_pos:
                logger.debug(f"Skipping overlapping match for pattern '{m['name']}' "
                             f"at positions {m['start']}-{m['end']}")
                continue

            # Add text before this match
            redacted_text_parts.append(text[last_pos:m['start']])

            # Add the placeholder for this match
            redacted_text_parts.append(m['placeholder'])

            # Record the redaction
            redactions.append({
                'pattern_name': m['name'],
                'placeholder': m['placeholder'],
                'start_pos': m['start'],
                'end_pos': m['end'],
                'matched_text': m['matched_text'],
                'replacement': m['placeholder']
            })

            # Update last position
            last_pos = m['end']

        # Add any remaining text after the last match
        redacted_text_parts.append(text[last_pos:])
        redacted_text = ''.join(redacted_text_parts)

        return {
            'redacted_text': redacted_text,
            'redactions': redactions,
            'total_redactions': len(redactions)
        }

    def get_pattern_summary(self, custom_config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a summary of all available redaction patterns.

        Args:
            custom_config_path: Optional path to custom configuration file

        Returns:
            Dictionary containing pattern summary information
        """
        patterns: List[Dict[str, Any]] = self.config_parser.get_regex_patterns(custom_config_path)

        summary: Dict[str, Any] = {
            'total_patterns': len(patterns),
            'categories': {},
            'pattern_details': []
        }

        for pattern in patterns:
            category = pattern.get('category', 'Unknown')
            if category not in summary['categories']:
                summary['categories'][category] = 0
            summary['categories'][category] += 1

            summary['pattern_details'].append({
                'name': pattern.get('name', 'unknown'),
                'category': category,
                'description': pattern.get('description', ''),
                'regex': pattern['regex'],
                'placeholder': pattern['placeholder']
            })

        return summary
