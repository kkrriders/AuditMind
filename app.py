

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import os
import uvicorn
import json
import re
from datetime import datetime

from audit_mind import AuditMindSimple


app = FastAPI(
    title="AuditMind API",
    description="AI-powered risk auditing for documents and code",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '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')
auditor = AuditMindSimple(openrouter_api_key=OPENROUTER_API_KEY, enable_llm=True)


def emergency_json_cleanup(response_text: str) -> str:
    """Emergency cleanup if JSON somehow gets through"""
    if not response_text:
        return response_text
    
    # Check for JSON in code blocks or direct JSON
    text = response_text.strip()
    
    # Handle JSON wrapped in code blocks
    if text.startswith('```json') or text.startswith('```'):
        print(f"[EMERGENCY] Code block JSON detected: {text[:100]}...")
        # Extract JSON from code block
        lines = text.split('\n')
        json_lines = []
        in_json = False
        for line in lines:
            if line.strip().startswith('```json') or (line.strip() == '```' and not in_json):
                in_json = True
                continue
            elif line.strip() == '```' and in_json:
                break
            elif in_json:
                json_lines.append(line)
        
        if json_lines:
            text = '\n'.join(json_lines).strip()
    
    # Check if it's JSON format
    if not (text.startswith('{') or text.startswith('[')):
        return response_text
    
    print(f"[EMERGENCY] JSON detected, performing cleanup: {text[:100]}...")
    
    try:
        # Try to parse and convert JSON to natural language
        import json
        data = json.loads(text)
        
        if isinstance(data, dict):
            # Convert common JSON structures to natural text
            parts = []
            
            # Handle summary
            if 'summary' in data:
                parts.append(data['summary'])
            elif 'issue' in data:
                parts.append(data['issue'])
            elif 'explanation' in data:
                parts.append(data['explanation'])
            
            # Handle best_practices with detailed structure
            if 'best_practices' in data:
                practices = data['best_practices']
                if isinstance(practices, list):
                    parts.append(" Here are the key practices you should follow:")
                    for practice in practices:
                        if isinstance(practice, dict):
                            name = practice.get('name', 'Practice')
                            description = practice.get('description', '')
                            steps = practice.get('actionable_steps', [])
                            impact = practice.get('impact', '')
                            
                            parts.append(f" {name}: {description}")
                            if isinstance(steps, list):
                                for step in steps:
                                    parts.append(f" {step}")
                            if impact:
                                parts.append(f" This {impact}")
                        else:
                            parts.append(f" {str(practice)}")
            
            # Handle recommendations
            if 'recommendations' in data:
                recommendations = data['recommendations']
                if isinstance(recommendations, list):
                    parts.append(" Here's what I recommend:")
                    for rec in recommendations:
                        if isinstance(rec, dict):
                            desc = rec.get('description', '')
                            details = rec.get('details', '')
                            parts.append(f" {desc} - {details}")
                        else:
                            parts.append(f" {str(rec)}")
            
            result = ''.join(parts)
            print(f"[EMERGENCY] Converted to natural language: {len(result)} chars")
            return result if result else "I can help you with security questions, but I'm having trouble formatting my response right now."
            
    except Exception as e:
        print(f"[EMERGENCY] Conversion failed: {e}")
        return "I can help you with security questions, but I'm having trouble formatting my response properly. Could you ask me again in a different way?"
    
    return response_text


class DocumentAnalysisRequest(BaseModel):
    document: str
    document_type: Optional[str] = "unknown"
    enable_llm: Optional[bool] = True

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None

class FileAnalysisRequest(BaseModel):
    filename: str
    content: str
    message: Optional[str] = "Analyze this file for security risks and vulnerabilities"
    context: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    llm_status = "disabled"
    working_models = []
    
    if auditor.enable_llm:
        # Test a few models to see which ones work
        test_models = [
            "openai/gpt-oss-20b:free",
            "openai/gpt-4o-mini-2024-07-18:free", 
            "google/gemma-2-9b-it:free"
        ]
        
        for model in test_models:
            try:
                # Temporarily set model and test
                original_model = auditor.llm.current_model
                auditor.llm.current_model = model
                test_response = auditor.llm.generate_response("Hello", max_tokens=10, response_format="natural")
                if test_response:
                    working_models.append(model)
                auditor.llm.current_model = original_model
            except Exception as e:
                continue
        
        llm_status = f"working models: {len(working_models)}"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "llm_enabled": auditor.enable_llm,
        "llm_status": llm_status,
        "working_models": working_models,
        "current_model": auditor.llm.current_model if auditor.enable_llm else None,
        "version": "1.0.0"
    }

@app.post("/analyze")
async def analyze_document(request: DocumentAnalysisRequest):
    """Analyze a document for risks"""
    try:
        if not request.document.strip():
            raise HTTPException(status_code=400, detail="Document cannot be empty")
        
       
        original_llm_state = auditor.enable_llm
        if not request.enable_llm:
            auditor.enable_llm = False
        
       
        result = auditor.analyze_document(
            document=request.document,
            doc_type=request.document_type
        )
        
       
        auditor.enable_llm = original_llm_state
        
        
        result["api_version"] = "1.0.0"
        result["request_id"] = f"req_{int(datetime.now().timestamp())}"
        
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis failed: {str(e)}"
        )

@app.post("/analyze/quick")
async def quick_analyze(request: DocumentAnalysisRequest):
    """Quick analysis without LLM (faster response)"""
    try:
        original_llm_state = auditor.enable_llm
        auditor.enable_llm = False
        
        result = auditor.analyze_document(
            document=request.document,
            doc_type=request.document_type
        )
        
        auditor.enable_llm = original_llm_state
        
        result["analysis_type"] = "quick"
        result["api_version"] = "1.0.0"
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models")
async def list_models():
    """List available models"""
    if not auditor.enable_llm:
        return {"message": "LLM not enabled"}
    
    return {
        "available_models": auditor.llm.free_models,
        "current_model": auditor.llm.current_model,
        "provider": "OpenRouter"
    }

@app.get("/example/security")
async def example_security():
    """Security example"""
    example = '''
    def login(username, password):
        api_key = "sk-1234567890abcdef"
        query = f"SELECT * FROM users WHERE name='{username}'"
        eval(user_input)
        return authenticate()
    '''
    result = auditor.analyze_document(example, "security_example")
    return result

@app.get("/example/privacy")
async def example_privacy():
    """Privacy example"""  
    example = '''
    We collect email addresses, phone numbers, and track user behavior.
    All interactions are logged including passwords for debugging.
    '''
    result = auditor.analyze_document(example, "privacy_example")
    return result

@app.post("/chat/test")
async def test_chat():
    """Simple chat test endpoint"""
    try:
        return {
            "response": "Test response - chat endpoint is working",
            "timestamp": datetime.now().isoformat(),
            "model_used": "test"
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/chat/simple") 
async def simple_chat(request: ChatRequest):
    """Simplified chat endpoint for debugging"""
    try:
        print(f"[SIMPLE_CHAT] Received: {request.message}")
        
        if not auditor.enable_llm:
            return {
                "response": "Sorry, AI chat is currently disabled.",
                "timestamp": datetime.now().isoformat(),
                "model_used": "none"
            }
        
        # Try a very simple prompt
        simple_prompt = f"Answer this question simply: {request.message}"
        
        response_text = auditor.llm.generate_response(
            simple_prompt, 
            max_tokens=800, 
            response_format="natural"
        )
        
        if not response_text:
            response_text = "Sorry, I couldn't process your request right now."
        
        print(f"[SIMPLE_CHAT] Response: {response_text[:50]}...")
        
        return {
            "response": response_text,
            "timestamp": datetime.now().isoformat(),
            "model_used": auditor.llm.current_model
        }
    except Exception as e:
        print(f"[SIMPLE_CHAT] Error: {e}")
        return {
            "response": f"Error occurred: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "model_used": "error"
        }

@app.post("/chat")
async def chat_with_ai(request: ChatRequest):
    """Chat with AI security assistant"""
    try:
        print(f"[CHAT] Received request: {request.message[:100]}...")
        
        if not auditor.enable_llm:
            print("[CHAT] LLM is disabled")
            raise HTTPException(status_code=503, detail="AI chat is not available (LLM disabled)")
        
        if not request.message.strip():
            print("[CHAT] Empty message")
            raise HTTPException(status_code=400, detail="Message cannot be empty")
        
        # Add context information to the user's question if provided
        enhanced_question = request.message
        if request.context:
            enhanced_question += f"\n\nContext from previous analysis: {request.context[:300]}..."
        
        # Add recent conversation for context
        if request.history:
            recent_history = request.history[-1:]  # Just the last message for context
            for msg in recent_history:
                if msg.get('role') == 'user':
                    enhanced_question += f"\n\nPrevious question: {msg.get('content', '')[:150]}..."
        
        # Use dedicated chat method that ONLY generates natural language
        print(f"[CHAT] Using chat-specific LLM method")
        print(f"[CHAT] Question: {request.message[:100]}...")
        
        response_text = auditor.llm.generate_chat_response(enhanced_question, max_tokens=1000)
        
        print(f"[CHAT] Chat LLM returned: {response_text[:100] if response_text else 'None'}...")
        
        if not response_text:
            # Fallback response if all models fail
            response_text = "I apologize, but I'm having trouble connecting to the AI service right now. This could be due to high demand or temporary service issues. Please try asking your question again in a moment."
        else:
            # Emergency JSON cleanup - if somehow JSON still comes through, convert it
            if ('```' in response_text or '{' in response_text or '[' in response_text):
                print(f"[CHAT] Structured data detected, performing emergency cleanup")
                response_text = emergency_json_cleanup(response_text)
                
                # If cleanup failed, try one more approach
                if ('```' in response_text or '{' in response_text):
                    print(f"[CHAT] Cleanup failed, trying natural language conversion")
                    conversion_prompt = f"Convert this technical response to natural, conversational language like you're explaining to a friend. Remove all JSON, code blocks, and structured formatting: {response_text[:500]}"
                    natural_response = auditor.llm.generate_chat_response(conversion_prompt, max_tokens=800)
                    if natural_response and not ('{' in natural_response or '```' in natural_response):
                        response_text = natural_response
        
        return {
            "response": response_text.strip(),
            "timestamp": datetime.now().isoformat(),
            "model_used": auditor.llm.current_model
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Chat error details: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Chat failed: {type(e).__name__}: {str(e)}"
        )

@app.post("/chat/analyze-file")
async def analyze_file_with_chat(request: FileAnalysisRequest):
    """Analyze uploaded file content and provide conversational response"""
    try:
        print(f"[FILE_CHAT] Analyzing file: {request.filename}")
        
        if not auditor.enable_llm:
            raise HTTPException(status_code=503, detail="AI analysis is not available (LLM disabled)")
        
        if not request.content.strip():
            raise HTTPException(status_code=400, detail="File content cannot be empty")
        
        # First, get a structured analysis of the file
        analysis_result = auditor.analyze_document(
            document=request.content,
            doc_type=request.filename.split('.')[-1] if '.' in request.filename else 'unknown'
        )
        
        # Create a comprehensive context for the chat response
        analysis_summary = f"File: {request.filename}\n"
        analysis_summary += f"Analysis Summary: {analysis_result.get('summary', '')}\n"
        
        if analysis_result.get('risks'):
            analysis_summary += f"Found {len(analysis_result['risks'])} security risks:\n"
            for i, risk in enumerate(analysis_result['risks'][:3], 1):  # Top 3 risks
                analysis_summary += f"{i}. {risk.get('issue', '')} (Severity: {risk.get('severity', 'unknown')})\n"
        
        # Enhance the user's question with file analysis context
        enhanced_question = f"{request.message}\n\nFile Analysis Context:\n{analysis_summary}"
        
        if request.context:
            enhanced_question += f"\n\nAdditional Context: {request.context[:200]}..."
        
        # Add recent conversation history
        if request.history:
            recent_history = request.history[-2:]  # Last 2 messages for context
            for msg in recent_history:
                if msg.get('role') == 'user':
                    enhanced_question += f"\n\nPrevious question: {msg.get('content', '')[:100]}..."
        
        # Generate conversational response
        response_text = auditor.llm.generate_chat_response(enhanced_question, max_tokens=1200)
        
        if not response_text:
            response_text = f"I've analyzed {request.filename} and found {len(analysis_result.get('risks', []))} potential security issues. However, I'm having trouble generating a detailed response right now. The main concerns include {', '.join([risk.get('category', 'security') for risk in analysis_result.get('risks', [])[:3]])} issues."
        else:
            # Emergency JSON cleanup
            if ('```' in response_text or '{' in response_text or '[' in response_text):
                response_text = emergency_json_cleanup(response_text)
        
        return {
            "response": response_text.strip(),
            "timestamp": datetime.now().isoformat(),
            "model_used": auditor.llm.current_model,
            "analysis_result": analysis_result,  # Include structured analysis for reference
            "file_info": {
                "filename": request.filename,
                "size": len(request.content),
                "risks_found": len(analysis_result.get('risks', []))
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"File chat error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"File analysis failed: {type(e).__name__}: {str(e)}"
        )

@app.get("/stats")
async def get_stats():
    """System statistics"""
    return {
        "service": "AuditMind API",
        "version": "1.0.0",
        "llm_enabled": auditor.enable_llm,
        "current_model": auditor.llm.current_model if auditor.enable_llm else None,
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 Starting AuditMind API on port {port}")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )