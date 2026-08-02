#!/usr/bin/env python3
"""
Bot Message command for the MeshCore Bot
Allows authorized users to send messages as using the bot's identity to channels via DM
"""

import time
from typing import Optional, Dict
from .base_command import BaseCommand
from ..models import MeshMessage
from ..security_utils import validate_pubkey_format


class BotMsgCommand(BaseCommand):
    """Handles botmsg command for sending messages to channels.
    
    Allows authorized users to send messages with bot's identity
    to specific channels. Requires specific ACL access and operates via DM only.
    """
    
    # Plugin metadata
    name = "botmsg"
    keywords = ['botmsg']
    description = "Send bot messages to channels (DM only, requires announcements ACL)"
    requires_dm = True
    category = "admin"
    
    def __init__(self, bot):
        super().__init__(bot)
        
        # Load configuration
        self.enabled = self.get_config_value('BotMsg_Command', 'enabled', fallback=False, value_type='bool')
        
        # Load announcements ACL (inherits admin ACL)
        self.botmsg_acl = self._load_botmsg_acl()
    
    def _load_botmsg_acl(self) -> list:
        """Load announcements ACL from config.
        
        Inherits members of admin ACL if botmsg_acl is not explicitly set.
        
        Returns:
            list: List of permitted public keys.
        """
        acl_list = []
        
        # First, get explicit botmsg_acl
        botmsg_acl_str = self.get_config_value('BotMsg_Command', 'botmsg_acl', fallback='', value_type='str')
        
        if botmsg_acl_str and botmsg_acl_str.strip():
            # Parse explicit botmsg ACL
            for key in botmsg_acl_str.split(','):
                key = key.strip()
                if not key:
                    continue
                if validate_pubkey_format(key, expected_length=64):
                    acl_list.append(key.lower())
                else:
                    self.logger.warning(f"Invalid pubkey in botmsg_acl: {key[:16]}...")
        
        # Always include admin ACL members (inheritance)
        try:
            admin_pubkeys = self.bot.config.get('Admin_ACL', 'admin_pubkeys', fallback='')
            if admin_pubkeys and admin_pubkeys.strip():
                for key in admin_pubkeys.split(','):
                    key = key.strip()
                    if not key:
                        continue
                    if validate_pubkey_format(key, expected_length=64):
                        normalized_key = key.lower()
                        # Add to list if not already present (avoid duplicates)
                        if normalized_key not in acl_list:
                            acl_list.append(normalized_key)
        except Exception as e:
            self.logger.debug(f"Error loading admin ACL for botmsg inheritance: {e}")
        
        return acl_list
    
    def _check_botmsg_access(self, message: MeshMessage) -> bool:
        """Check if the message sender has botmsg access.
        
        Uses the same security-hardened approach as admin ACL checking.
        
        Args:
            message: The message to check access for.
            
        Returns:
            bool: True if access is granted, False otherwise.
        """
        if not hasattr(self.bot, 'config'):
            return False
        
        if not self.botmsg_acl:
            self.logger.warning("No botmsg ACL configured")
            return False
        
        # Get sender's public key - NEVER fall back to sender_id
        sender_pubkey = getattr(message, 'sender_pubkey', None)
        if not sender_pubkey:
            self.logger.warning(
                f"No sender public key available for {message.sender_id} - "
                "botmsg access denied (missing pubkey)"
            )
            return False
        
        # Validate sender pubkey format
        if not validate_pubkey_format(sender_pubkey, expected_length=64):
            self.logger.warning(
                f"Invalid sender pubkey format from {message.sender_id}: "
                f"{sender_pubkey[:16]}... - botmsg access denied"
            )
            return False
        
        # Normalize and compare
        sender_pubkey_normalized = sender_pubkey.lower()
        has_access = sender_pubkey_normalized in self.botmsg_acl
        
        if not has_access:
            self.logger.warning(
                f"botmsg access denied for {message.sender_id} "
                f"(pubkey: {sender_pubkey[:16]}...) - not in announcements ACL"
            )
        else:
            self.logger.info(
                f"botmsg access granted for {message.sender_id} "
                f"(pubkey: {sender_pubkey[:16]}...)"
            )
        
        return has_access
    
    def can_execute(self, message: MeshMessage) -> bool:
        """Check if botmsg command can be executed.
        
        Args:
            message: The message trigger.
            
        Returns:
            bool: True if allowed to execute.
        """
        # Check if command is enabled
        if not self.enabled:
            return False
        
        # Check if message is DM (required)
        if not message.is_dm:
            return False
        
        # Check botmsg ACL access
        if not self._check_botmsg_access(message):
            return False
        
        return True
    
    def _parse_command(self, content: str) -> tuple:
        """Parse the botmsg command.
        
        Format: botmsg <channel> <message>
        
        Args:
            content: Command content string.
            
        Returns:
            tuple: (channel_name, msg) or (None, None) if invalid.
        """
        parts = content.strip().split(None, 2)
        if len(parts) < 3:
            return (None, None)
        
        channel_name = parts[1].strip()
        msg = parts[2].strip()
        
        return (channel_name, msg)
    
    async def execute(self, message: MeshMessage) -> bool:
        """Execute the announcements command.
        
        Args:
            message: The input message trigger.
            
        Returns:
            bool: True if execution was successful.
        """
        try:
            # Parse command
            channel_name, msg = self._parse_command(message.content)
            
            # Determine channel
            target_channel = channel_name
            
            # Send announcement to channel
            success = await self.bot.command_manager.send_channel_message(target_channel, msg)
            
            if success:
                await self.send_response(
                    message,
                    f"botmsg '{msg}' sent to {target_channel}"
                )
                self.logger.info(
                    f"User {message.sender_id} sent botmsg '{msg}' to {target_channel}"
                )
            else:
                await self.send_response(
                    message,
                    f"Failed to send botmsg to {target_channel}"
                )
                self.logger.error(
                    f"Failed to send botmsg '{msg}' to {target_channel}"
                )
            
            return True
            
        except Exception as e:
            error_msg = f"Error sending botmsg: {str(e)}"
            self.logger.error(f"Error in botmsg command: {e}")
            await self.send_response(message, error_msg)
            return False

