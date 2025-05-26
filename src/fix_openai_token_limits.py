#!/usr/bin/env python3
# Save as: src/fix_openai_token_limits.py
# This module fixes OpenAI API token limit issues

import json
import logging
import tiktoken
from typing import List, Dict, Any, Optional
import time

logger = logging.getLogger(__name__)

class OpenAITokenManager:
    """Manages OpenAI API requests to avoid token limits"""
    
    def __init__(self, model: str = "gpt-4", max_tokens: int = 4000):
        self.model = model
        self.max_tokens = max_tokens
        self.encoding = tiktoken.encoding_for_model(model)
        
        # Reserve tokens for response
        self.response_token_reserve = 1000
        self.max_prompt_tokens = max_tokens - self.response_token_reserve
        
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        return len(self.encoding.encode(text))
    
    def chunk_data(self, data: List[Any], prompt_template: str, max_items_per_chunk: int = 20) -> List[List[Any]]:
        """Chunk data to fit within token limits"""
        chunks = []
        current_chunk = []
        current_tokens = self.count_tokens(prompt_template)
        
        for item in data:
            item_str = json.dumps(item)
            item_tokens = self.count_tokens(item_str)
            
            # Check if adding this item would exceed limit
            if current_tokens + item_tokens > self.max_prompt_tokens or len(current_chunk) >= max_items_per_chunk:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = [item]
                current_tokens = self.count_tokens(prompt_template) + item_tokens
            else:
                current_chunk.append(item)
                current_tokens += item_tokens
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def create_efficient_prompt(self, purpose: str, data: Any, instructions: str) -> str:
        """Create token-efficient prompts"""
        # Minimize prompt size while maintaining clarity
        prompt = f"""Purpose: {purpose}
Data: {json.dumps(data, separators=(',', ':'))}
Instructions: {instructions}
Output: JSON only, no explanation."""
        
        # Check token count
        token_count = self.count_tokens(prompt)
        if token_count > self.max_prompt_tokens:
            # Truncate data if needed
            truncated_data = str(data)[:self.max_prompt_tokens * 4]  # Rough estimate
            prompt = f"""Purpose: {purpose}
Data (truncated): {truncated_data}...
Instructions: {instructions}
Output: JSON only."""
        
        return prompt

class EnhancedOpenAIHandler:
    """Enhanced OpenAI API handler with retry logic and token management"""
    
    def __init__(self, client, token_manager: OpenAITokenManager):
        self.client = client
        self.token_manager = token_manager
        self.max_retries = 3
        self.base_delay = 2
        
    async def make_request_with_retry(self, messages: List[Dict], temperature: float = 0.7) -> Optional[str]:
        """Make OpenAI request with retry logic and error handling"""
        for attempt in range(self.max_retries):
            try:
                response = await self.client.chat.completions.create(
                    model=self.token_manager.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=self.token_manager.response_token_reserve
                )
                
                if response and response.choices and response.choices[0].message:
                    return response.choices[0].message.content
                    
            except Exception as e:
                error_str = str(e)
                
                if "maximum context length" in error_str or "token" in error_str.lower():
                    logger.error(f"Token limit exceeded on attempt {attempt + 1}")
                    # Reduce message size and retry
                    messages = self._reduce_message_size(messages)
                elif "rate_limit" in error_str:
                    logger.warning(f"Rate limit hit, waiting {self.base_delay * (attempt + 1)}s")
                    time.sleep(self.base_delay * (attempt + 1))
                else:
                    logger.error(f"OpenAI API error: {e}")
                    
                if attempt == self.max_retries - 1:
                    return None
                    
        return None
    
    def _reduce_message_size(self, messages: List[Dict]) -> List[Dict]:
        """Reduce message size to fit token limits"""
        if not messages:
            return messages
            
        # Get the user message and reduce its content
        for msg in messages:
            if msg.get('role') == 'user':
                content = msg['content']
                # Keep first 75% of content
                msg['content'] = content[:int(len(content) * 0.75)] + "\n[Content truncated due to token limits]"
                
        return messages

# Patch for the assistant's AI classification method
def create_patched_ai_classify_endpoints(token_manager: OpenAITokenManager, handler: EnhancedOpenAIHandler):
    """Create a patched version of _ai_classify_endpoints with proper token management"""
    
    def _ai_classify_endpoints_patched(self, endpoints: List[Dict]) -> List[Dict]:
        """Patched version with token management"""
        if not endpoints:
            return []
        
        logger.info(f"Starting AI classification for {len(endpoints)} endpoints with token management")
        
        # Limit endpoints first
        max_endpoints = 200  # Reduced from 500
        if len(endpoints) > max_endpoints:
            logger.warning(f"Limiting endpoints to {max_endpoints}")
            # Prioritize interesting endpoints
            interesting = [e for e in endpoints if e.get("interesting", False)]
            non_interesting = [e for e in endpoints if not e.get("interesting", False)]
            
            if len(interesting) > max_endpoints:
                endpoints = interesting[:max_endpoints]
            else:
                remaining = max_endpoints - len(interesting)
                endpoints = interesting + non_interesting[:remaining]
        
        # Create efficient prompt template
        prompt_template = """Analyze endpoints for bug bounty hunting.
Focus on: admin interfaces, file uploads, APIs, auth mechanisms, configs, dev artifacts.
For each endpoint return: url, interest_level (high/medium/low), potential_vulnerabilities[], priority (1-10).
Output format: {"endpoints": [...]}"""
        
        # Chunk endpoints
        chunks = token_manager.chunk_data(endpoints, prompt_template, max_items_per_chunk=25)
        classified_endpoints = []
        
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{len(chunks)} ({len(chunk)} endpoints)")
            
            try:
                prompt = token_manager.create_efficient_prompt(
                    purpose="Endpoint classification for bug bounty",
                    data=chunk,
                    instructions="Classify each endpoint by vulnerability potential. Return JSON with 'endpoints' array."
                )
                
                messages = [{"role": "user", "content": prompt}]
                
                # Use async handler if available, otherwise sync
                import asyncio
                if asyncio.get_event_loop().is_running():
                    content = asyncio.create_task(handler.make_request_with_retry(messages, temperature=0.3)).result()
                else:
                    # Sync version
                    content = handler.make_request_with_retry(messages, temperature=0.3)
                
                if content:
                    try:
                        result = json.loads(content)
                        classified_endpoints.extend(result.get("endpoints", chunk))
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse AI response for chunk {i+1}, using defaults")
                        for endpoint in chunk:
                            endpoint["interest_level"] = "medium"
                            endpoint["potential_vulnerabilities"] = []
                        classified_endpoints.extend(chunk)
                else:
                    # Fallback
                    classified_endpoints.extend(chunk)
                    
            except Exception as e:
                logger.error(f"Error in AI classification for chunk {i+1}: {e}")
                classified_endpoints.extend(chunk)
            
            # Rate limiting between chunks
            if i < len(chunks) - 1:
                time.sleep(2)
        
        logger.info(f"Completed AI classification for {len(classified_endpoints)} endpoints")
        return classified_endpoints
    
    return _ai_classify_endpoints_patched
