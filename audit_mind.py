

import json
import re
import os
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class RiskCategory(Enum):
    SECURITY = "security"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"
    ETHICAL_FAIRNESS = "ethical/fairness"
    OPERATIONAL = "operational"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Risk:
    id: str
    category: RiskCategory
    severity: Severity
    issue: str
    explanation: str
    suggested_mitigation: str
    confidence: float = 0.8


class SimpleOpenRouterClient:
    """Simple OpenRouter client using requests (no dependency issues)"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://auditMind.com",
            "X-Title": "AuditMind Risk Auditor"
        }
        self.free_models = [
            "openai/gpt-oss-20b:free",
            "openai/gpt-4o-mini",
            "openai/gpt-3.5-turbo", 
            "meta-llama/llama-3.1-8b-instruct:free",
            "google/gemma-2-9b-it:free",
            "meta-llama/llama-3.2-3b-instruct:free",
            "microsoft/wizardlm-2-8x22b:free", 
            "mistralai/mistral-7b-instruct:free"
        ]
        self.current_model = self.free_models[0]  
    
    def set_model(self, model_name: str):
        """Set the model to use"""
        if model_name in self.free_models:
            self.current_model = model_name
        else:
            print(f"Warning: {model_name} not in free models list.")
    
    def generate_response(self, prompt: str, max_tokens: int = 1500, response_format: str = "json") -> Optional[str]:
        """Generate response using direct HTTP requests with model fallback"""
        # Choose system message based on response format
        if response_format == "natural":
            system_content = """You are a helpful security expert. CRITICAL INSTRUCTION: You must respond in natural, conversational English. Do not use JSON, objects, lists, code blocks, or any structured formats. Write like you're explaining to a colleague in person using normal sentences and paragraphs. Start your response immediately with helpful information - no JSON objects allowed."""
        else:
            system_content = "You are an expert security auditor. Provide concise analysis in JSON format."
        
        # Adjust temperature based on response format
        temperature = 0.7 if response_format == "natural" else 0.3
        
        # Try multiple models if primary fails
        models_to_try = [self.current_model] + [m for m in self.free_models[:3] if m != self.current_model]
        
        for model_name in models_to_try:
            try:
                payload = {
                    "model": model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": system_content
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        }
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "top_p": 1.0
                }
                
                print(f"Trying model: {model_name}")
                
                # Small delay to prevent rate limiting
                time.sleep(0.5)
                
                response = requests.post(
                    self.base_url,
                    headers=self.headers,
                    json=payload,
                    timeout=20  # Reduced timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'choices' in data and len(data['choices']) > 0:
                        content = data['choices'][0]['message']['content'].strip()
                        finish_reason = data['choices'][0].get('finish_reason', 'unknown')
                        
                        # Check if response was truncated
                        if finish_reason == 'length':
                            print(f"Warning: Response truncated due to token limit with model {model_name}")
                            # Try to extend with continuation if possible
                            if len(content) > 50:  # Only continue if we got substantial content
                                continuation_prompt = f"Please continue and complete this response: {content[-100:]}"
                                try:
                                    continuation_payload = payload.copy()
                                    continuation_payload['messages'][-1]['content'] = continuation_prompt
                                    continuation_payload['max_tokens'] = min(500, max_tokens // 2)
                                    
                                    continuation_response = requests.post(
                                        self.base_url,
                                        headers=self.headers,
                                        json=continuation_payload,
                                        timeout=20
                                    )
                                    
                                    if continuation_response.status_code == 200:
                                        continuation_data = continuation_response.json()
                                        if 'choices' in continuation_data and len(continuation_data['choices']) > 0:
                                            continuation_content = continuation_data['choices'][0]['message']['content'].strip()
                                            # Merge responses intelligently
                                            if continuation_content and not continuation_content.startswith(content[-50:]):
                                                content = content + " " + continuation_content
                                                print(f"Extended response with continuation")
                                except Exception as e:
                                    print(f"Continuation failed: {e}")
                        
                        print(f"Success with model: {model_name} (finish_reason: {finish_reason})")
                        return content
                    else:
                        print(f"Model {model_name}: Invalid response format - {data}")
                        continue
                else:
                    error_text = response.text if response.text else "No error message"
                    print(f"Model {model_name} failed ({response.status_code}): {error_text}")
                    continue
                    
            except requests.exceptions.Timeout:
                print(f"Model {model_name}: Request timeout")
                continue
            except requests.exceptions.ConnectionError as e:
                print(f"Model {model_name}: Connection failed - {str(e)}")
                continue
            except Exception as e:
                print(f"Model {model_name}: {type(e).__name__}: {str(e)}")
                continue
        
        print("All models failed")
        return None

    def generate_chat_response(self, prompt: str, max_tokens: int = 1200) -> Optional[str]:
        """Generate conversational response - NO JSON ALLOWED"""
        # Ultra-strong natural language system prompt
        system_content = """You are a friendly cybersecurity expert talking to someone. You must respond like a normal human conversation - NO technical formatting allowed.

CRITICAL: If you use ANY of these formats, the system will reject your response:
- JSON objects like {"key": "value"}  
- Arrays like ["item1", "item2"]
- Code blocks with ```
- Structured lists with bullets
- Any curly braces {} or square brackets []

ONLY respond in natural speech like this example:
"SQL injection is a serious security vulnerability where attackers manipulate database queries by inserting malicious code through user input. To protect against this, you should always use parameterized queries instead of string concatenation. Also make sure to validate all user inputs and limit database permissions. These steps will significantly reduce your attack surface."

Talk naturally like you're having coffee with a friend."""

        # Use GPT OSS model first, with fallbacks
        chat_models = [
            "openai/gpt-oss-20b:free",  # Primary choice
            "google/gemma-2-9b-it:free",  # Fallback 1
            "mistralai/mistral-7b-instruct:free"  # Fallback 2
        ]
        
        for model_name in chat_models:
            try:
                payload = {
                    "model": model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": system_content
                        },
                        {
                            "role": "user", 
                            "content": f"Please explain this in natural conversation style: {prompt}"
                        }
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.8,  # Higher temperature for more natural responses
                    "top_p": 0.9,
                    "frequency_penalty": 0.3,  # Reduce repetitive patterns
                    "presence_penalty": 0.1
                }
                
                print(f"[CHAT_LLM] Trying model: {model_name}")
                
                # Small delay to prevent rate limiting
                time.sleep(0.3)
                
                response = requests.post(
                    self.base_url,
                    headers=self.headers,
                    json=payload,
                    timeout=25
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'choices' in data and len(data['choices']) > 0:
                        response_text = data['choices'][0]['message']['content'].strip()
                        
                        # Check if response contains JSON-like structures or structured data
                        if ('{' in response_text or '[' in response_text or '```' in response_text or 
                            '"' in response_text[:50] or response_text.strip().startswith('{') or
                            'json' in response_text.lower()[:100]):
                            print(f"[CHAT_LLM] Model {model_name} returned structured data: {response_text[:100]}...")
                            print(f"[CHAT_LLM] Rejecting and trying next model")
                            continue
                        
                        print(f"[CHAT_LLM] Success with model: {model_name}")
                        return response_text
                    else:
                        print(f"[CHAT_LLM] Model {model_name}: Invalid response format")
                        continue
                else:
                    error_text = response.text if response.text else "No error message"
                    print(f"[CHAT_LLM] Model {model_name} failed ({response.status_code}): {error_text}")
                    continue
                    
            except Exception as e:
                print(f"[CHAT_LLM] Model {model_name}: {type(e).__name__}: {str(e)}")
                continue
        
        print("[CHAT_LLM] All chat models failed")
        return None


class AuditMindSimple:
    """Simple AuditMind without OpenAI client dependencies"""
    
    def __init__(self, openrouter_api_key: str = None, enable_llm: bool = True):
        self.enable_llm = enable_llm and openrouter_api_key is not None
        self.llm = SimpleOpenRouterClient(openrouter_api_key) if self.enable_llm else None
        self.risk_patterns = self._initialize_risk_patterns()
        
        print(f"🤖 AuditMind initialized - LLM: {'Enabled' if self.enable_llm else 'Disabled'}")
        if self.enable_llm:
            print(f"   Using model: {self.llm.current_model}")
    
    def _initialize_risk_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize risk detection patterns"""
        return {
            'security': [
                {
                    'pattern': r'(?i)(password|pwd|secret|key|token|api_key)\s*=\s*["\'][^"\']{3,}["\']',
                    'issue': 'Hardcoded credentials detected',
                    'explanation': 'Hardcoded credentials can be exposed in version control',
                    'mitigation': 'Use environment variables or secure credential management',
                    'severity': Severity.HIGH
                },
                {
                    'pattern': r'(?i)sk-[a-zA-Z0-9]{10,}',
                    'issue': 'Hardcoded API key detected',
                    'explanation': 'API keys in source code can be exposed and misused',
                    'mitigation': 'Move API keys to environment variables',
                    'severity': Severity.HIGH
                },
                {
                    'pattern': r'(?i)(eval|exec|system|shell_exec)\s*\(',
                    'issue': 'Code execution function detected',
                    'explanation': 'Dynamic code execution can lead to injection vulnerabilities',
                    'mitigation': 'Avoid dynamic code execution, use safe alternatives',
                    'severity': Severity.HIGH
                },
                {
                    'pattern': r'(?i)(http://|ftp://)',
                    'issue': 'Insecure protocol usage',
                    'explanation': 'Unencrypted protocols expose data in transit',
                    'mitigation': 'Use HTTPS/FTPS instead of HTTP/FTP',
                    'severity': Severity.MEDIUM
                }
            ],
            'privacy': [
                {
                    'pattern': r'(?i)(email|phone|ssn|social security|credit card)',
                    'issue': 'Potential PII handling detected',
                    'explanation': 'PII requires special handling and protection',
                    'mitigation': 'Implement encryption, access controls, privacy compliance',
                    'severity': Severity.HIGH
                },
                {
                    'pattern': r'(?i)(track|analytics|pixel|beacon)',
                    'issue': 'Tracking mechanism detected',
                    'explanation': 'User tracking may violate privacy regulations',
                    'mitigation': 'Implement proper consent and privacy disclosures',
                    'severity': Severity.MEDIUM
                }
            ],
            'operational': [
                {
                    'pattern': r'(?i)(todo|fixme|hack|workaround)',
                    'issue': 'Technical debt markers detected',
                    'explanation': 'Temporary solutions can become permanent issues',
                    'mitigation': 'Create tickets to address technical debt',
                    'severity': Severity.LOW
                }
            ]
        }

    def analyze_document(self, document: str, doc_type: str = "unknown") -> Dict[str, Any]:
        """Analyze document for risks"""
        risks = []
        risk_counter = {"SEC": 1, "PRI": 1, "OPS": 1}
        
        # Pattern-based detection
        for category, patterns in self.risk_patterns.items():
            category_prefix = {
                'security': 'SEC',
                'privacy': 'PRI', 
                'operational': 'OPS'
            }.get(category, 'GEN')
            
            for pattern_config in patterns:
                matches = re.finditer(pattern_config['pattern'], document, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    if category_prefix in risk_counter:
                        risk_id = f"{category_prefix}{risk_counter[category_prefix]:03d}"
                        risk_counter[category_prefix] += 1
                        
                        risk = Risk(
                            id=risk_id,
                            category=RiskCategory(category.replace('_', '/')),
                            severity=pattern_config['severity'],
                            issue=pattern_config['issue'],
                            explanation=pattern_config['explanation'],
                            suggested_mitigation=pattern_config['mitigation'],
                            confidence=0.9
                        )
                        risks.append(risk)
        
        # Sort by severity
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        risks.sort(key=lambda r: severity_order[r.severity])
        
        # Get LLM analysis if enabled
        llm_analysis = {}
        if self.enable_llm and risks:
            llm_analysis = self._get_llm_analysis(document, risks)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "document_type": doc_type,
            "analysis_method": "pattern + llm" if self.enable_llm else "pattern-based",
            "summary": f"Found {len(risks)} potential risks" if risks else "No risks detected",
            "risks": [
                {
                    "id": risk.id,
                    "category": risk.category.value,
                    "severity": risk.severity.value,
                    "issue": risk.issue,
                    "explanation": risk.explanation,
                    "suggested_mitigation": risk.suggested_mitigation,
                    "confidence": risk.confidence
                }
                for risk in risks
            ],
            "llm_insights": llm_analysis,
            "uncertain": False
        }

    def _get_llm_analysis(self, document: str, detected_risks: List[Risk]) -> Dict[str, Any]:
        """Get LLM analysis"""
        if not self.enable_llm:
            return {}
        
        risk_summary = f"Found {len(detected_risks)} risks: " + ", ".join([r.issue for r in detected_risks[:3]])
        
        prompt = f"""
Analyze this document:

DOCUMENT:
{document[:1000]}

DETECTED RISKS: {risk_summary}

Provide JSON response:
{{
  "overall_risk_level": "low|medium|high|critical",
  "key_concerns": ["concern1", "concern2"],
  "recommendations": ["action1", "action2"]
}}

Return only JSON.
"""
        
        try:
            response = self.llm.generate_response(prompt, max_tokens=300, response_format="json")
            if response:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    return json.loads(response[json_start:json_end])
            return {}
        except Exception as e:
            print(f"LLM error: {e}")
            return {}


if __name__ == "__main__":
    api_key = os.getenv('OPENROUTER_API_KEY')
    auditor = AuditMindSimple(openrouter_api_key=api_key, enable_llm=True)
    
    
    test_doc = 'api_key = "sk-test123456789"'
    result = auditor.analyze_document(test_doc)
    print(json.dumps(result, indent=2))