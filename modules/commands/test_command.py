#!/usr/bin/env python3
"""
Test command for the MeshCore Bot
Handles the 'test' keyword response
"""

import re
from .base_command import BaseCommand
from ..models import MeshMessage


class TestCommand(BaseCommand):
    """Handles the test command"""
    
    # Plugin metadata
    name = "test"
    keywords = ['test', 't']
    description = "Responds to 'test' or 't' with connection info"
    category = "basic"
    
    def get_help_text(self) -> str:
        return self.description
    
    def clean_content(self, content: str) -> str:
        """Clean content by removing control characters and normalizing whitespace"""
        import re
        # Remove control characters (except newline, tab, carriage return)
        cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
        # Normalize whitespace
        cleaned = ' '.join(cleaned.split())
        return cleaned
    
    def matches_keyword(self, message: MeshMessage) -> bool:
        """Override to implement special test keyword matching with optional phrase"""
        # Clean content to remove control characters and normalize whitespace
        content = self.clean_content(message.content)
        
        # Strip exclamation mark if present (for command-style messages)
        if content.startswith('!'):
            content = content[1:].strip()
        
        # Handle "test" alone or "test " with phrase
        if content.lower() == "test":
            return True  # Just "test" by itself
        elif (content.startswith('test ') or content.startswith('Test ')) and len(content) > 5:
            phrase = content[5:].strip()  # Get everything after "test " and strip whitespace
            return bool(phrase)  # Make sure there's actually a phrase
        
        # Handle "t" alone or "t " with phrase
        elif content.lower() == "t":
            return True  # Just "t" by itself
        elif (content.startswith('t ') or content.startswith('T ')) and len(content) > 2:
            phrase = content[2:].strip()  # Get everything after "t " and strip whitespace
            return bool(phrase)  # Make sure there's actually a phrase
        
        return False
    
    def get_response_format(self) -> str:
        """Get the response format from config"""
        if self.bot.config.has_section('Keywords'):
            format_str = self.bot.config.get('Keywords', 'test', fallback=None)
            return self._strip_quotes_from_config(format_str) if format_str else None
        return None
    
    def format_response(self, message: MeshMessage, response_format: str) -> str:
        """Override to handle phrase extraction"""
        # Clean content to remove control characters and normalize whitespace
        content = self.clean_content(message.content)
        
        # Strip exclamation mark if present (for command-style messages)
        if content.startswith('!'):
            content = content[1:].strip()
        
        # Extract phrase if present, otherwise use empty string
        if content.lower() == "test":
            phrase = ""
        elif content.lower() == "t":
            phrase = ""
        elif content.startswith('test ') or content.startswith('Test '):
            phrase = content[5:].strip()  # Get everything after "test "
        elif content.startswith('t ') or content.startswith('T '):
            phrase = content[2:].strip()  # Get everything after "t "
        else:
            phrase = ""
        
        try:
            connection_info = self.build_enhanced_connection_info(message)
            timestamp = self.format_timestamp(message)
            
            # Format phrase part - add colon and space if phrase exists
            phrase_part = f": {phrase}" if phrase else ""
            
            return response_format.format(
                sender=message.sender_id or "Unknown",
                phrase=phrase,
                phrase_part=phrase_part,
                connection_info=connection_info,
                path=message.path or "Unknown",
                timestamp=timestamp,
                snr=message.snr or "Unknown"
            )
        except (KeyError, ValueError) as e:
            self.logger.warning(f"Error formatting test response: {e}")
            return response_format
    
    async def execute(self, message: MeshMessage) -> bool:
        """Execute the test command"""
        return await self.handle_keyword_match(message)
